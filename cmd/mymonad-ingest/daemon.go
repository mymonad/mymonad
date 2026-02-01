package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mymonad/mymonad/internal/config"
	"github.com/mymonad/mymonad/internal/embed"
	"github.com/mymonad/mymonad/internal/ingest"
	"github.com/mymonad/mymonad/internal/ipc"
	"github.com/mymonad/mymonad/pkg/monad"
)

// Daemon states.
const (
	StateIdle       = "idle"
	StateProcessing = "processing"
	StateError      = "error"
)

// DaemonConfig holds configuration for the ingest daemon.
type DaemonConfig struct {
	SocketPath    string
	MonadPath     string
	WatchDirs     []string
	Extensions    []string
	IgnoreHidden  bool
	OllamaURL     string
	OllamaModel   string
	OllamaTimeout int
	Dimensions    int // 768 for nomic-embed-text
}

// Validate checks that all required configuration fields are set.
func (c *DaemonConfig) Validate() error {
	if c.SocketPath == "" {
		return errors.New("socket path is required")
	}
	if c.MonadPath == "" {
		return errors.New("monad path is required")
	}
	if c.OllamaURL == "" {
		return errors.New("ollama URL is required")
	}
	if c.Dimensions <= 0 {
		return errors.New("dimensions must be positive")
	}
	// Default timeout if not set
	if c.OllamaTimeout <= 0 {
		c.OllamaTimeout = 30
	}
	return nil
}

// DefaultDaemonConfig returns a DaemonConfig with sensible defaults.
func DefaultDaemonConfig() DaemonConfig {
	paths := config.DefaultPaths()
	return DaemonConfig{
		SocketPath:    paths.IngestSocket,
		MonadPath:     paths.MonadPath,
		WatchDirs:     []string{},
		Extensions:    []string{".txt", ".md"},
		IgnoreHidden:  true,
		OllamaURL:     "http://localhost:11434",
		OllamaModel:   "nomic-embed-text",
		OllamaTimeout: 30,
		Dimensions:    768,
	}
}

// Daemon is the ingest daemon that watches files and updates the Monad.
type Daemon struct {
	cfg       DaemonConfig
	monad     *monad.Monad
	watchers  []*ingest.Watcher
	processor *embed.Processor
	server    *ipc.Server
	logger    *slog.Logger

	// State tracking
	state   string
	stateMu sync.RWMutex

	// Event channel
	events chan ingest.FileEvent
}

// NewDaemon creates a new ingest daemon.
// If embedder is nil, it creates an OllamaClient from config.
func NewDaemon(cfg DaemonConfig, embedder embed.Embedder) (*Daemon, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Create logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Load or create monad
	var m *monad.Monad
	if _, err := os.Stat(cfg.MonadPath); err == nil {
		// Load existing monad
		m, err = monad.LoadFromFile(cfg.MonadPath)
		if err != nil {
			logger.Warn("failed to load existing monad, creating new one",
				"path", cfg.MonadPath,
				"error", err,
			)
			m = monad.New(cfg.Dimensions)
		} else {
			logger.Info("loaded existing monad",
				"path", cfg.MonadPath,
				"version", m.Version,
				"docCount", m.DocCount,
			)
		}
	} else {
		// Create new monad
		m = monad.New(cfg.Dimensions)
		logger.Info("created new monad", "dimensions", cfg.Dimensions)
	}

	// Create embedder if not provided
	if embedder == nil {
		embedder = embed.NewOllamaClient(cfg.OllamaURL, cfg.OllamaModel, cfg.OllamaTimeout)
	}

	// Create processor with max tokens for chunking
	processor := embed.NewProcessor(embedder, 512)

	d := &Daemon{
		cfg:       cfg,
		monad:     m,
		processor: processor,
		logger:    logger,
		state:     StateIdle,
		events:    make(chan ingest.FileEvent, 100),
	}

	return d, nil
}

// Run starts the daemon and blocks until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	// Ensure data directory exists
	if err := os.MkdirAll(filepath.Dir(d.cfg.MonadPath), 0700); err != nil {
		return err
	}

	// Start IPC server
	server, err := ipc.NewServer(d.cfg.SocketPath, d)
	if err != nil {
		return err
	}
	d.server = server

	// Start server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		d.logger.Info("starting IPC server", "socket", d.cfg.SocketPath)
		serverErr <- server.Start()
	}()

	// Start file watchers
	if err := d.startWatchers(ctx); err != nil {
		d.server.Stop()
		return err
	}

	// Start event processor
	go d.processEvents(ctx)

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		d.logger.Info("shutting down daemon")
	case err := <-serverErr:
		d.logger.Error("server error", "error", err)
	}

	// Graceful shutdown
	return d.shutdown()
}

// startWatchers initializes file watchers for all configured directories.
func (d *Daemon) startWatchers(ctx context.Context) error {
	for _, dir := range d.cfg.WatchDirs {
		// Expand path
		expandedDir := config.ExpandPath(dir)

		watcher, err := ingest.NewWatcher(expandedDir, d.events)
		if err != nil {
			d.logger.Warn("failed to create watcher",
				"dir", dir,
				"error", err,
			)
			continue
		}

		// Set up error callback
		watcher.SetErrorCallback(func(err error) {
			d.logger.Error("watcher error", "error", err)
		})

		d.watchers = append(d.watchers, watcher)

		// Start watcher in goroutine
		go func(w *ingest.Watcher, watchDir string) {
			d.logger.Info("watching directory", "dir", watchDir)
			w.Start(ctx)
		}(watcher, expandedDir)
	}

	return nil
}

// processEvents handles file events from watchers.
func (d *Daemon) processEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-d.events:
			if !ok {
				return
			}
			d.handleFileEvent(ctx, event)
		}
	}
}

// handleFileEvent processes a single file event.
func (d *Daemon) handleFileEvent(ctx context.Context, event ingest.FileEvent) {
	// Check if file extension is supported
	ext := strings.ToLower(filepath.Ext(event.Path))
	if !d.isExtensionSupported(ext) {
		return
	}

	// Check for hidden files
	if d.cfg.IgnoreHidden && isHiddenFile(event.Path) {
		return
	}

	switch event.Op {
	case ingest.OpCreate, ingest.OpModify:
		d.processFile(ctx, event.Path)
	case ingest.OpDelete:
		// For delete, we could track file contributions and remove them
		// For now, we just log it
		d.logger.Info("file deleted", "path", event.Path)
	}
}

// processFile reads, chunks, embeds, and updates the monad with a file.
func (d *Daemon) processFile(ctx context.Context, path string) {
	d.setState(StateProcessing)
	defer d.setState(StateIdle)

	d.logger.Info("processing file", "path", path)

	embedding, err := d.processor.ProcessFile(ctx, path)
	if err != nil {
		if errors.Is(err, embed.ErrUnsupportedFormat) {
			d.logger.Debug("unsupported file format", "path", path)
			return
		}
		if errors.Is(err, embed.ErrEmptyFile) {
			d.logger.Debug("empty file", "path", path)
			return
		}
		d.logger.Error("failed to process file", "path", path, "error", err)
		return
	}

	if err := d.monad.Update(embedding); err != nil {
		d.logger.Error("failed to update monad", "path", path, "error", err)
		return
	}

	d.logger.Info("file processed",
		"path", path,
		"monadVersion", d.monad.Version,
		"docCount", d.monad.DocCount,
	)
}

// isExtensionSupported checks if the file extension is in the configured list.
func (d *Daemon) isExtensionSupported(ext string) bool {
	if len(d.cfg.Extensions) == 0 {
		// If no extensions configured, use default supported extensions
		return embed.SupportedExtensions[ext]
	}
	for _, supported := range d.cfg.Extensions {
		if ext == supported {
			return true
		}
	}
	return false
}

// isHiddenFile checks if any component of the path starts with a dot.
func isHiddenFile(path string) bool {
	for _, part := range strings.Split(path, string(os.PathSeparator)) {
		if len(part) > 0 && part[0] == '.' {
			return true
		}
	}
	return false
}

// shutdown performs graceful shutdown: stops server, watchers, saves monad.
func (d *Daemon) shutdown() error {
	var errs []error

	// Stop watchers
	for _, w := range d.watchers {
		if err := w.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	// Stop server
	if d.server != nil {
		if err := d.server.Stop(); err != nil {
			errs = append(errs, err)
		}
	}

	// Save monad
	if err := d.saveMonad(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// saveMonad saves the monad to disk.
func (d *Daemon) saveMonad() error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(d.cfg.MonadPath), 0700); err != nil {
		return err
	}

	if err := monad.SaveToFile(d.monad, d.cfg.MonadPath); err != nil {
		d.logger.Error("failed to save monad", "path", d.cfg.MonadPath, "error", err)
		return err
	}

	d.logger.Info("monad saved",
		"path", d.cfg.MonadPath,
		"version", d.monad.Version,
		"docCount", d.monad.DocCount,
	)
	return nil
}

// setState updates the daemon state.
func (d *Daemon) setState(state string) {
	d.stateMu.Lock()
	defer d.stateMu.Unlock()
	d.state = state
}

// GetMonad implements ipc.MonadProvider.
func (d *Daemon) GetMonad() ([]byte, int64, error) {
	data, err := d.monad.MarshalBinary()
	if err != nil {
		return nil, 0, err
	}
	return data, d.monad.Version, nil
}

// GetStatus implements ipc.MonadProvider.
func (d *Daemon) GetStatus() (ready bool, docsIndexed int64, state string) {
	d.stateMu.RLock()
	defer d.stateMu.RUnlock()
	return true, d.monad.DocCount, d.state
}

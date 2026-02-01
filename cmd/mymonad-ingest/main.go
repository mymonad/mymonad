package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mymonad/mymonad/internal/config"
)

func main() {
	// Define command-line flags
	configPath := flag.String("config", "", "Path to TOML configuration file")
	watchDirsFlag := flag.String("watch-dirs", "", "Comma-separated list of directories to watch")
	ollamaURL := flag.String("ollama-url", "", "Ollama API URL (default: http://localhost:11434)")
	ollamaModel := flag.String("model", "", "Ollama embedding model (default: nomic-embed-text)")
	socketPath := flag.String("socket", "", "Unix socket path for IPC")
	logLevel := flag.String("log-level", "info", "Log level: debug, info, warn, error")

	flag.Parse()

	// Set up logger based on log level
	var level slog.Level
	switch strings.ToLower(*logLevel) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	// Build configuration
	cfg, err := buildConfig(*configPath, *watchDirsFlag, *ollamaURL, *ollamaModel, *socketPath)
	if err != nil {
		logger.Error("failed to build configuration", "error", err)
		os.Exit(1)
	}

	// Ensure directories exist
	paths := config.DefaultPaths()
	if err := paths.EnsureDirectories(); err != nil {
		logger.Error("failed to create directories", "error", err)
		os.Exit(1)
	}

	// Create daemon
	daemon, err := NewDaemon(cfg, nil)
	if err != nil {
		logger.Error("failed to create daemon", "error", err)
		os.Exit(1)
	}

	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig.String())
		cancel()
	}()

	// Run daemon
	logger.Info("starting mymonad-ingest daemon",
		"watchDirs", cfg.WatchDirs,
		"socket", cfg.SocketPath,
		"ollamaURL", cfg.OllamaURL,
		"model", cfg.OllamaModel,
	)

	if err := daemon.Run(ctx); err != nil && err != context.Canceled {
		logger.Error("daemon error", "error", err)
		os.Exit(1)
	}

	logger.Info("daemon stopped gracefully")
}

// buildConfig creates a DaemonConfig from file and/or flags.
// Flags override file settings.
func buildConfig(configPath, watchDirs, ollamaURL, ollamaModel, socketPath string) (DaemonConfig, error) {
	var cfg DaemonConfig

	// Load from file if provided
	if configPath != "" {
		fileCfg, err := config.LoadIngestConfig(configPath)
		if err != nil {
			return cfg, fmt.Errorf("failed to load config file: %w", err)
		}

		// Map config file to DaemonConfig
		paths := config.DefaultPaths()
		cfg = DaemonConfig{
			SocketPath:    paths.IngestSocket,
			MonadPath:     fileCfg.Storage.MonadPath,
			WatchDirs:     fileCfg.Watch.Directories,
			Extensions:    fileCfg.Watch.Extensions,
			IgnoreHidden:  fileCfg.Watch.IgnoreHidden,
			OllamaURL:     fileCfg.Ollama.URL,
			OllamaModel:   fileCfg.Ollama.Model,
			OllamaTimeout: fileCfg.Ollama.TimeoutSeconds,
			Dimensions:    768, // nomic-embed-text dimension
		}
	} else {
		// Start with defaults
		cfg = DefaultDaemonConfig()
	}

	// Override with flags
	if watchDirs != "" {
		dirs := strings.Split(watchDirs, ",")
		for i, dir := range dirs {
			dirs[i] = strings.TrimSpace(config.ExpandPath(dir))
		}
		cfg.WatchDirs = dirs
	}

	if ollamaURL != "" {
		cfg.OllamaURL = ollamaURL
	}

	if ollamaModel != "" {
		cfg.OllamaModel = ollamaModel
	}

	if socketPath != "" {
		cfg.SocketPath = socketPath
	}

	// Validate final config
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

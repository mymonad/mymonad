package ingest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/fsnotify/fsnotify"
)

// Op represents the type of file operation.
type Op int

const (
	OpCreate Op = iota
	OpModify
	OpDelete
)

// String returns a human-readable representation of the operation.
func (o Op) String() string {
	switch o {
	case OpCreate:
		return "Create"
	case OpModify:
		return "Modify"
	case OpDelete:
		return "Delete"
	default:
		return "Unknown"
	}
}

// FileEvent represents a file system event.
type FileEvent struct {
	Path string
	Op   Op
}

// ErrorCallback is called when an error occurs during watching.
type ErrorCallback func(err error)

// SkippedPath represents a path that was skipped during initial scan.
type SkippedPath struct {
	Path string
	Err  error
}

// Watcher monitors a directory for file changes.
type Watcher struct {
	root     string
	events   chan<- FileEvent
	fsw      *fsnotify.Watcher
	excludes []string
	mu       sync.RWMutex // protects excludes and skippedPaths

	// Error handling
	onError      ErrorCallback
	droppedCount atomic.Int64
	skippedPaths []SkippedPath

	// Cancellation
	done chan struct{}
}

// DefaultExcludes are patterns to ignore.
var DefaultExcludes = []string{
	".git",
	"node_modules",
	".cache",
	"__pycache__",
	".tmp",
}

// NewWatcher creates a new file watcher for the given directory.
// Returns an error if root does not exist or is not a directory.
func NewWatcher(root string, events chan<- FileEvent) (*Watcher, error) {
	// Validate that root exists and is a directory
	info, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("root directory does not exist: %s", root)
		}
		return nil, fmt.Errorf("cannot access root directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("root is not a directory: %s", root)
	}

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	w := &Watcher{
		root:         root,
		events:       events,
		fsw:          fsw,
		excludes:     append([]string(nil), DefaultExcludes...), // defensive copy
		done:         make(chan struct{}),
		skippedPaths: make([]SkippedPath, 0),
	}

	// Add root and subdirectories
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Track skipped paths instead of silently ignoring
			w.mu.Lock()
			w.skippedPaths = append(w.skippedPaths, SkippedPath{Path: path, Err: err})
			w.mu.Unlock()
			return nil
		}
		if info.IsDir() {
			if w.shouldExclude(path) {
				return filepath.SkipDir
			}
			return fsw.Add(path)
		}
		return nil
	})
	if err != nil {
		fsw.Close()
		return nil, err
	}

	return w, nil
}

// SetExcludes sets the list of patterns to exclude from watching.
// This is safe to call concurrently with Start().
func (w *Watcher) SetExcludes(excludes []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.excludes = append([]string(nil), excludes...) // defensive copy
}

// SetErrorCallback sets a callback function that will be called when errors occur.
func (w *Watcher) SetErrorCallback(cb ErrorCallback) {
	w.onError = cb
}

// DroppedEventCount returns the number of events that were dropped due to channel full.
func (w *Watcher) DroppedEventCount() int64 {
	return w.droppedCount.Load()
}

// SkippedPaths returns paths that were skipped during initial scan due to errors.
// This is useful for detecting permission issues or other access problems.
func (w *Watcher) SkippedPaths() []SkippedPath {
	w.mu.RLock()
	defer w.mu.RUnlock()
	// Return a copy to prevent external modification
	result := make([]SkippedPath, len(w.skippedPaths))
	copy(result, w.skippedPaths)
	return result
}

// shouldExclude checks if a path should be excluded.
// Uses exact base name matching (e.g., ".git" only matches ".git", not "my.git_folder").
func (w *Watcher) shouldExclude(path string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()

	base := filepath.Base(path)
	for _, exc := range w.excludes {
		if base == exc {
			return true
		}
	}
	return false
}

// Start begins watching for events (blocking).
// Returns when the context is cancelled or Close() is called.
func (w *Watcher) Start(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case event, ok := <-w.fsw.Events:
			if !ok {
				return
			}

			if w.shouldExclude(event.Name) {
				continue
			}

			var op Op
			switch {
			case event.Op&fsnotify.Create != 0:
				op = OpCreate
				// If it's a new directory, add it to watch
				if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
					w.fsw.Add(event.Name)
				}
			case event.Op&fsnotify.Write != 0:
				op = OpModify
			case event.Op&fsnotify.Remove != 0:
				op = OpDelete
			default:
				continue
			}

			// Non-blocking send to prevent blocking when channel is full
			select {
			case w.events <- FileEvent{
				Path: event.Name,
				Op:   op,
			}:
				// Event sent successfully
			default:
				// Channel full, drop the event and count it
				w.droppedCount.Add(1)
			}

		case err, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			// Report error via callback if set
			if w.onError != nil {
				w.onError(err)
			}
		}
	}
}

// Close stops the watcher and signals Start() to return.
func (w *Watcher) Close() error {
	// Signal done channel to stop Start() loop
	select {
	case <-w.done:
		// Already closed
	default:
		close(w.done)
	}
	return w.fsw.Close()
}

// ErrRootNotExist is returned when the root directory does not exist.
var ErrRootNotExist = errors.New("root directory does not exist")

// ErrRootNotDirectory is returned when the root path is not a directory.
var ErrRootNotDirectory = errors.New("root is not a directory")

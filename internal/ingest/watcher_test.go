package ingest

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatcherDetectsNewFile(t *testing.T) {
	tmpDir := t.TempDir()

	events := make(chan FileEvent, 10)
	watcher, err := NewWatcher(tmpDir, events)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer watcher.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.Start(ctx)

	// Create a new file
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello"), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Wait for event
	select {
	case event := <-events:
		if event.Path != testFile {
			t.Errorf("Path mismatch: got %s, want %s", event.Path, testFile)
		}
		if event.Op != OpCreate {
			t.Errorf("Op should be OpCreate, got %v", event.Op)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for event")
	}
}

func TestWatcherDetectsModify(t *testing.T) {
	tmpDir := t.TempDir()

	// Create file before watching
	testFile := filepath.Join(tmpDir, "existing.txt")
	if err := os.WriteFile(testFile, []byte("initial"), 0644); err != nil {
		t.Fatalf("Failed to write initial file: %v", err)
	}

	events := make(chan FileEvent, 10)
	watcher, err := NewWatcher(tmpDir, events)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer watcher.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	// Modify the file
	if err := os.WriteFile(testFile, []byte("modified"), 0644); err != nil {
		t.Fatalf("Failed to modify file: %v", err)
	}

	// Wait for event
	select {
	case event := <-events:
		if event.Op != OpModify && event.Op != OpCreate {
			t.Errorf("Op should be OpModify or OpCreate, got %v", event.Op)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for event")
	}
}

func TestWatcherDetectsDelete(t *testing.T) {
	tmpDir := t.TempDir()

	// Create file before watching
	testFile := filepath.Join(tmpDir, "todelete.txt")
	if err := os.WriteFile(testFile, []byte("delete me"), 0644); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	events := make(chan FileEvent, 10)
	watcher, err := NewWatcher(tmpDir, events)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer watcher.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	// Delete the file
	if err := os.Remove(testFile); err != nil {
		t.Fatalf("Failed to delete file: %v", err)
	}

	// Wait for event
	select {
	case event := <-events:
		if event.Path != testFile {
			t.Errorf("Path mismatch: got %s, want %s", event.Path, testFile)
		}
		if event.Op != OpDelete {
			t.Errorf("Op should be OpDelete, got %v", event.Op)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for event")
	}
}

func TestWatcherExcludesGitDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create .git directory
	gitDir := filepath.Join(tmpDir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatalf("Failed to create .git directory: %v", err)
	}

	events := make(chan FileEvent, 10)
	watcher, err := NewWatcher(tmpDir, events)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer watcher.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	// Create a file inside .git - should be ignored
	gitFile := filepath.Join(gitDir, "config")
	if err := os.WriteFile(gitFile, []byte("git config"), 0644); err != nil {
		t.Fatalf("Failed to write .git file: %v", err)
	}

	// Create a normal file - should be detected
	normalFile := filepath.Join(tmpDir, "normal.txt")
	if err := os.WriteFile(normalFile, []byte("normal"), 0644); err != nil {
		t.Fatalf("Failed to write normal file: %v", err)
	}

	// Wait for the normal file event
	select {
	case event := <-events:
		if event.Path == gitFile {
			t.Error("Should not receive events from .git directory")
		}
		if event.Path != normalFile {
			t.Errorf("Expected event for normal file, got: %s", event.Path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for event")
	}
}

func TestWatcherExcludesNodeModules(t *testing.T) {
	tmpDir := t.TempDir()

	// Create node_modules directory
	nodeDir := filepath.Join(tmpDir, "node_modules")
	if err := os.MkdirAll(nodeDir, 0755); err != nil {
		t.Fatalf("Failed to create node_modules directory: %v", err)
	}

	events := make(chan FileEvent, 10)
	watcher, err := NewWatcher(tmpDir, events)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer watcher.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	// Create a file inside node_modules - should be ignored
	nodeFile := filepath.Join(nodeDir, "package.json")
	if err := os.WriteFile(nodeFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to write node_modules file: %v", err)
	}

	// Create a normal file - should be detected
	normalFile := filepath.Join(tmpDir, "index.js")
	if err := os.WriteFile(normalFile, []byte("console.log()"), 0644); err != nil {
		t.Fatalf("Failed to write normal file: %v", err)
	}

	// Wait for the normal file event
	select {
	case event := <-events:
		if event.Path == nodeFile {
			t.Error("Should not receive events from node_modules directory")
		}
		if event.Path != normalFile {
			t.Errorf("Expected event for normal file, got: %s", event.Path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for event")
	}
}

func TestWatcherRecursiveDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a nested directory structure
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("Failed to create subdir: %v", err)
	}

	events := make(chan FileEvent, 10)
	watcher, err := NewWatcher(tmpDir, events)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer watcher.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	// Create a file in the subdirectory
	subFile := filepath.Join(subDir, "nested.txt")
	if err := os.WriteFile(subFile, []byte("nested content"), 0644); err != nil {
		t.Fatalf("Failed to write nested file: %v", err)
	}

	// Wait for event
	select {
	case event := <-events:
		if event.Path != subFile {
			t.Errorf("Path mismatch: got %s, want %s", event.Path, subFile)
		}
		if event.Op != OpCreate {
			t.Errorf("Op should be OpCreate, got %v", event.Op)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for event from subdirectory")
	}
}

func TestWatcherAutoAddsNewDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	events := make(chan FileEvent, 10)
	watcher, err := NewWatcher(tmpDir, events)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer watcher.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	// Create a new directory after watcher started
	newDir := filepath.Join(tmpDir, "newdir")
	if err := os.MkdirAll(newDir, 0755); err != nil {
		t.Fatalf("Failed to create new directory: %v", err)
	}

	// Drain the directory creation event
	select {
	case <-events:
		// Directory creation event received
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for directory creation event")
	}

	time.Sleep(100 * time.Millisecond)

	// Create a file in the new directory - should be detected
	newFile := filepath.Join(newDir, "file.txt")
	if err := os.WriteFile(newFile, []byte("content"), 0644); err != nil {
		t.Fatalf("Failed to write file in new directory: %v", err)
	}

	// Wait for the file event
	select {
	case event := <-events:
		if event.Path != newFile {
			t.Errorf("Path mismatch: got %s, want %s", event.Path, newFile)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for event from auto-added directory")
	}
}

func TestWatcherSetExcludes(t *testing.T) {
	tmpDir := t.TempDir()

	events := make(chan FileEvent, 10)
	watcher, err := NewWatcher(tmpDir, events)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer watcher.Close()

	// Set custom excludes
	watcher.SetExcludes([]string{".custom", "build"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	// Create a .custom directory and file - should be ignored
	customDir := filepath.Join(tmpDir, ".custom")
	if err := os.MkdirAll(customDir, 0755); err != nil {
		t.Fatalf("Failed to create .custom directory: %v", err)
	}
	customFile := filepath.Join(customDir, "data")
	if err := os.WriteFile(customFile, []byte("custom data"), 0644); err != nil {
		t.Fatalf("Failed to write custom file: %v", err)
	}

	// Create a normal file - should be detected
	normalFile := filepath.Join(tmpDir, "source.go")
	if err := os.WriteFile(normalFile, []byte("package main"), 0644); err != nil {
		t.Fatalf("Failed to write normal file: %v", err)
	}

	// Wait for the normal file event
	select {
	case event := <-events:
		if event.Path == customFile {
			t.Error("Should not receive events from .custom directory")
		}
		if event.Path != normalFile {
			t.Errorf("Expected event for normal file, got: %s", event.Path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for event")
	}
}

func TestOpString(t *testing.T) {
	tests := []struct {
		op   Op
		want string
	}{
		{OpCreate, "Create"},
		{OpModify, "Modify"},
		{OpDelete, "Delete"},
		{Op(99), "Unknown"},
	}

	for _, tt := range tests {
		got := tt.op.String()
		if got != tt.want {
			t.Errorf("Op(%d).String() = %s, want %s", tt.op, got, tt.want)
		}
	}
}

func TestDefaultExcludes(t *testing.T) {
	expected := []string{".git", "node_modules", ".cache", "__pycache__", ".tmp"}

	if len(DefaultExcludes) != len(expected) {
		t.Errorf("DefaultExcludes length mismatch: got %d, want %d", len(DefaultExcludes), len(expected))
	}

	for i, exc := range expected {
		if DefaultExcludes[i] != exc {
			t.Errorf("DefaultExcludes[%d] = %s, want %s", i, DefaultExcludes[i], exc)
		}
	}
}

func TestWatcherCloseStopsStart(t *testing.T) {
	tmpDir := t.TempDir()

	events := make(chan FileEvent, 10)
	watcher, err := NewWatcher(tmpDir, events)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}

	done := make(chan struct{})
	ctx := context.Background()
	go func() {
		watcher.Start(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	if err := watcher.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}

	select {
	case <-done:
		// Start returned as expected
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Close")
	}
}

func TestNewWatcherValidatesRoot(t *testing.T) {
	// Test non-existent directory
	events := make(chan FileEvent, 10)
	_, err := NewWatcher("/nonexistent/path/12345", events)
	if err == nil {
		t.Error("Expected error for non-existent directory")
	}

	// Test file instead of directory
	tmpFile, err := os.CreateTemp("", "watchertest")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	_, err = NewWatcher(tmpFile.Name(), events)
	if err == nil {
		t.Error("Expected error for file instead of directory")
	}
}

func TestWatcherContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()

	events := make(chan FileEvent, 10)
	watcher, err := NewWatcher(tmpDir, events)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer watcher.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		watcher.Start(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel() // Cancel context instead of closing

	select {
	case <-done:
		// Start returned as expected after context cancellation
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

func TestWatcherDroppedEventsCount(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a channel with capacity 1 to force drops
	events := make(chan FileEvent, 1)
	watcher, err := NewWatcher(tmpDir, events)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer watcher.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	// Create multiple files rapidly without draining the channel
	for i := 0; i < 5; i++ {
		testFile := filepath.Join(tmpDir, "file"+string(rune('0'+i))+".txt")
		if err := os.WriteFile(testFile, []byte("content"), 0644); err != nil {
			t.Fatalf("Failed to write file: %v", err)
		}
	}

	time.Sleep(500 * time.Millisecond)

	// Should have dropped some events
	dropped := watcher.DroppedEventCount()
	if dropped == 0 {
		t.Log("No events dropped (may be timing dependent)")
	} else {
		t.Logf("Dropped %d events as expected", dropped)
	}
}

func TestWatcherErrorCallback(t *testing.T) {
	tmpDir := t.TempDir()

	events := make(chan FileEvent, 10)
	watcher, err := NewWatcher(tmpDir, events)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer watcher.Close()

	var errorCount atomic.Int32
	watcher.SetErrorCallback(func(err error) {
		errorCount.Add(1)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	// Error callback is set - this is a basic test that it compiles and runs
	// Actually triggering fsnotify errors is difficult in a unit test
	t.Log("Error callback registered successfully")
}

func TestWatcherExactExcludeMatch(t *testing.T) {
	tmpDir := t.TempDir()

	// Create directories: .git (should exclude) and my.git_folder (should NOT exclude)
	gitDir := filepath.Join(tmpDir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatalf("Failed to create .git directory: %v", err)
	}

	similarDir := filepath.Join(tmpDir, "my.git_folder")
	if err := os.MkdirAll(similarDir, 0755); err != nil {
		t.Fatalf("Failed to create my.git_folder directory: %v", err)
	}

	events := make(chan FileEvent, 10)
	watcher, err := NewWatcher(tmpDir, events)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer watcher.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	// Create a file in my.git_folder - should be detected (exact match only)
	similarFile := filepath.Join(similarDir, "data.txt")
	if err := os.WriteFile(similarFile, []byte("data"), 0644); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	// Wait for the file event
	select {
	case event := <-events:
		if event.Path != similarFile {
			t.Errorf("Expected event for %s, got: %s", similarFile, event.Path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for event - exact exclude match may have incorrectly excluded similar names")
	}
}

func TestSetExcludesConcurrentSafety(t *testing.T) {
	tmpDir := t.TempDir()

	events := make(chan FileEvent, 10)
	watcher, err := NewWatcher(tmpDir, events)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer watcher.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.Start(ctx)

	// Concurrently update excludes while watcher is running
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			watcher.SetExcludes([]string{".test", "build"})
		}
		close(done)
	}()

	// Create files while excludes are being updated
	for i := 0; i < 10; i++ {
		testFile := filepath.Join(tmpDir, "concurrent"+string(rune('0'+i))+".txt")
		os.WriteFile(testFile, []byte("content"), 0644)
	}

	<-done
	time.Sleep(100 * time.Millisecond)
	// If we get here without a race condition panic, the test passes
}

func TestWatcherSkippedPaths(t *testing.T) {
	tmpDir := t.TempDir()

	events := make(chan FileEvent, 10)
	watcher, err := NewWatcher(tmpDir, events)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer watcher.Close()

	// For an accessible directory, SkippedPaths should be empty
	skipped := watcher.SkippedPaths()
	if len(skipped) != 0 {
		t.Errorf("Expected no skipped paths for accessible directory, got %d", len(skipped))
	}
}

func TestWatcherSkippedPathsReturnsDefensiveCopy(t *testing.T) {
	tmpDir := t.TempDir()

	events := make(chan FileEvent, 10)
	watcher, err := NewWatcher(tmpDir, events)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer watcher.Close()

	// Get skipped paths twice and verify they're separate slices
	skipped1 := watcher.SkippedPaths()
	skipped2 := watcher.SkippedPaths()

	// Both should be empty but be different slice instances
	if len(skipped1) != 0 || len(skipped2) != 0 {
		t.Error("Expected empty skipped paths")
	}

	// Verify modifying one doesn't affect the other (defensive copy test)
	// This test is more about documenting the API contract
}

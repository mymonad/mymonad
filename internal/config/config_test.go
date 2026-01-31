// internal/config/config_test.go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExpandPath_TildeExpansion(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("failed to get home dir: %v", err)
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"~/Documents", filepath.Join(home, "Documents")},
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
		{"~", home},
	}

	for _, tt := range tests {
		result := ExpandPath(tt.input)
		if result != tt.expected {
			t.Errorf("ExpandPath(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestDefaultPaths(t *testing.T) {
	paths := DefaultPaths()

	if paths.ConfigDir == "" {
		t.Error("ConfigDir should not be empty")
	}
	if paths.DataDir == "" {
		t.Error("DataDir should not be empty")
	}
	if paths.IngestSocket == "" {
		t.Error("IngestSocket should not be empty")
	}
	if paths.AgentSocket == "" {
		t.Error("AgentSocket should not be empty")
	}
}

func TestEnsureDirectories(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()

	paths := Paths{
		ConfigDir: filepath.Join(tmpDir, "config", "mymonad"),
		DataDir:   filepath.Join(tmpDir, "data", "mymonad"),
	}

	// Directories should not exist yet
	if _, err := os.Stat(paths.ConfigDir); !os.IsNotExist(err) {
		t.Fatal("ConfigDir should not exist before EnsureDirectories")
	}
	if _, err := os.Stat(paths.DataDir); !os.IsNotExist(err) {
		t.Fatal("DataDir should not exist before EnsureDirectories")
	}

	// Create directories
	if err := paths.EnsureDirectories(); err != nil {
		t.Fatalf("EnsureDirectories failed: %v", err)
	}

	// Verify directories exist
	info, err := os.Stat(paths.ConfigDir)
	if err != nil {
		t.Fatalf("ConfigDir should exist after EnsureDirectories: %v", err)
	}
	if !info.IsDir() {
		t.Error("ConfigDir should be a directory")
	}

	info, err = os.Stat(paths.DataDir)
	if err != nil {
		t.Fatalf("DataDir should exist after EnsureDirectories: %v", err)
	}
	if !info.IsDir() {
		t.Error("DataDir should be a directory")
	}

	// Calling EnsureDirectories again should be idempotent
	if err := paths.EnsureDirectories(); err != nil {
		t.Fatalf("EnsureDirectories should be idempotent: %v", err)
	}
}

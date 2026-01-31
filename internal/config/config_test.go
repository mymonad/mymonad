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

func TestIngestConfig_LoadFromTOML(t *testing.T) {
	tomlContent := `
[watch]
directories = ["~/Documents", "~/Notes"]
extensions = [".txt", ".md"]
ignore_hidden = true

[ollama]
url = "http://localhost:11434"
model = "nomic-embed-text"
timeout_seconds = 30
`
	tmpFile := filepath.Join(t.TempDir(), "ingest.toml")
	if err := os.WriteFile(tmpFile, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	cfg, err := LoadIngestConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadIngestConfig failed: %v", err)
	}

	if len(cfg.Watch.Directories) != 2 {
		t.Errorf("expected 2 directories, got %d", len(cfg.Watch.Directories))
	}
	if cfg.Ollama.Model != "nomic-embed-text" {
		t.Errorf("expected model nomic-embed-text, got %s", cfg.Ollama.Model)
	}
	if cfg.Ollama.TimeoutSeconds != 30 {
		t.Errorf("expected timeout 30, got %d", cfg.Ollama.TimeoutSeconds)
	}
}

func TestAgentConfig_LoadFromTOML(t *testing.T) {
	tomlContent := `
[network]
port = 4001

[discovery]
dns_seeds = ["_dnsaddr.bootstrap.mymonad.net"]
bootstrap = ["/ip4/192.168.1.1/tcp/4001/p2p/12D3KooTest"]
mdns_enabled = false

[protocol]
similarity_threshold = 0.7
challenge_difficulty = 20
`
	tmpFile := filepath.Join(t.TempDir(), "agent.toml")
	if err := os.WriteFile(tmpFile, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	cfg, err := LoadAgentConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadAgentConfig failed: %v", err)
	}

	if cfg.Network.Port != 4001 {
		t.Errorf("expected port 4001, got %d", cfg.Network.Port)
	}
	if cfg.Protocol.SimilarityThreshold != 0.7 {
		t.Errorf("expected threshold 0.7, got %f", cfg.Protocol.SimilarityThreshold)
	}
	if cfg.Discovery.MDNSEnabled {
		t.Error("expected mdns_enabled false")
	}
}

func TestIngestConfig_Defaults(t *testing.T) {
	cfg := DefaultIngestConfig()

	if cfg.Ollama.URL != "http://localhost:11434" {
		t.Errorf("expected default Ollama URL, got %s", cfg.Ollama.URL)
	}
	if cfg.Ollama.Model != "nomic-embed-text" {
		t.Errorf("expected default model, got %s", cfg.Ollama.Model)
	}
}

func TestAgentConfig_Defaults(t *testing.T) {
	cfg := DefaultAgentConfig()

	if cfg.Network.Port != 4001 {
		t.Errorf("expected default port 4001, got %d", cfg.Network.Port)
	}
	if cfg.Protocol.SimilarityThreshold != 0.85 {
		t.Errorf("expected default similarity threshold 0.85, got %f", cfg.Protocol.SimilarityThreshold)
	}
	if cfg.Protocol.ChallengeDifficulty != 16 {
		t.Errorf("expected default challenge difficulty 16, got %d", cfg.Protocol.ChallengeDifficulty)
	}
}

func TestIngestConfig_PathExpansion(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("failed to get home dir: %v", err)
	}

	tomlContent := `
[watch]
directories = ["~/Documents", "~/Notes"]
extensions = [".txt"]
ignore_hidden = true

[storage]
monad_path = "~/data/monad.bin"
`
	tmpFile := filepath.Join(t.TempDir(), "ingest.toml")
	if err := os.WriteFile(tmpFile, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	cfg, err := LoadIngestConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadIngestConfig failed: %v", err)
	}

	// Verify paths are expanded
	expectedDir := filepath.Join(home, "Documents")
	if cfg.Watch.Directories[0] != expectedDir {
		t.Errorf("expected directory %s, got %s", expectedDir, cfg.Watch.Directories[0])
	}

	expectedMonadPath := filepath.Join(home, "data", "monad.bin")
	if cfg.Storage.MonadPath != expectedMonadPath {
		t.Errorf("expected monad path %s, got %s", expectedMonadPath, cfg.Storage.MonadPath)
	}
}

func TestLoadIngestConfig_FileNotFound(t *testing.T) {
	_, err := LoadIngestConfig("/nonexistent/path/config.toml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadAgentConfig_FileNotFound(t *testing.T) {
	_, err := LoadAgentConfig("/nonexistent/path/config.toml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadIngestConfig_InvalidTOML(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "invalid.toml")
	if err := os.WriteFile(tmpFile, []byte("this is not valid [ toml"), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := LoadIngestConfig(tmpFile)
	if err == nil {
		t.Error("expected error for invalid TOML")
	}
}

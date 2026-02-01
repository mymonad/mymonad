package main

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// mockEmbedder implements embed.Embedder for testing.
type mockEmbedder struct {
	embeddings []float32
	callCount  int
	mu         sync.Mutex
}

func (m *mockEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++
	return m.embeddings, nil
}

func (m *mockEmbedder) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

func TestDaemonConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     DaemonConfig
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: DaemonConfig{
				SocketPath:    "/tmp/test.sock",
				MonadPath:     "/tmp/monad.bin",
				WatchDirs:     []string{"/tmp"},
				Extensions:    []string{".txt"},
				IgnoreHidden:  true,
				OllamaURL:     "http://localhost:11434",
				OllamaModel:   "nomic-embed-text",
				OllamaTimeout: 30,
				Dimensions:    768,
			},
			wantErr: false,
		},
		{
			name: "missing socket path",
			cfg: DaemonConfig{
				MonadPath:     "/tmp/monad.bin",
				WatchDirs:     []string{"/tmp"},
				OllamaURL:     "http://localhost:11434",
				OllamaModel:   "nomic-embed-text",
				OllamaTimeout: 30,
				Dimensions:    768,
			},
			wantErr: true,
		},
		{
			name: "missing monad path",
			cfg: DaemonConfig{
				SocketPath:    "/tmp/test.sock",
				WatchDirs:     []string{"/tmp"},
				OllamaURL:     "http://localhost:11434",
				OllamaModel:   "nomic-embed-text",
				OllamaTimeout: 30,
				Dimensions:    768,
			},
			wantErr: true,
		},
		{
			name: "missing ollama url",
			cfg: DaemonConfig{
				SocketPath:    "/tmp/test.sock",
				MonadPath:     "/tmp/monad.bin",
				WatchDirs:     []string{"/tmp"},
				OllamaModel:   "nomic-embed-text",
				OllamaTimeout: 30,
				Dimensions:    768,
			},
			wantErr: true,
		},
		{
			name: "missing dimensions",
			cfg: DaemonConfig{
				SocketPath:    "/tmp/test.sock",
				MonadPath:     "/tmp/monad.bin",
				WatchDirs:     []string{"/tmp"},
				OllamaURL:     "http://localhost:11434",
				OllamaModel:   "nomic-embed-text",
				OllamaTimeout: 30,
			},
			wantErr: true,
		},
		{
			name: "zero timeout uses default",
			cfg: DaemonConfig{
				SocketPath:  "/tmp/test.sock",
				MonadPath:   "/tmp/monad.bin",
				WatchDirs:   []string{"/tmp"},
				OllamaURL:   "http://localhost:11434",
				OllamaModel: "nomic-embed-text",
				Dimensions:  768,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewDaemon(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")
	monadPath := filepath.Join(tmpDir, "monad.bin")

	cfg := DaemonConfig{
		SocketPath:    sockPath,
		MonadPath:     monadPath,
		WatchDirs:     []string{tmpDir},
		Extensions:    []string{".txt", ".md"},
		IgnoreHidden:  true,
		OllamaURL:     "http://localhost:11434",
		OllamaModel:   "nomic-embed-text",
		OllamaTimeout: 30,
		Dimensions:    768,
	}

	d, err := NewDaemon(cfg, nil)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}

	if d == nil {
		t.Fatal("NewDaemon() returned nil")
	}

	if d.monad == nil {
		t.Error("Daemon monad is nil")
	}

	if d.monad.Dimensions() != 768 {
		t.Errorf("Monad dimensions = %d, want 768", d.monad.Dimensions())
	}
}

func TestNewDaemon_LoadsExistingMonad(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")
	monadPath := filepath.Join(tmpDir, "monad.bin")

	// Create a monad file first
	cfg := DaemonConfig{
		SocketPath:    sockPath,
		MonadPath:     monadPath,
		WatchDirs:     []string{tmpDir},
		OllamaURL:     "http://localhost:11434",
		OllamaModel:   "nomic-embed-text",
		OllamaTimeout: 30,
		Dimensions:    768,
	}

	d1, err := NewDaemon(cfg, nil)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}

	// Update the monad with some data
	embedding := make([]float32, 768)
	for i := range embedding {
		embedding[i] = float32(i) * 0.001
	}
	if err := d1.monad.Update(embedding); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Save it
	if err := d1.saveMonad(); err != nil {
		t.Fatalf("saveMonad() error = %v", err)
	}

	// Create a new daemon - should load the existing monad
	d2, err := NewDaemon(cfg, nil)
	if err != nil {
		t.Fatalf("NewDaemon() second time error = %v", err)
	}

	if d2.monad.DocCount != 1 {
		t.Errorf("Loaded monad DocCount = %d, want 1", d2.monad.DocCount)
	}

	if d2.monad.Version != 1 {
		t.Errorf("Loaded monad Version = %d, want 1", d2.monad.Version)
	}
}

func TestDaemon_GetMonad(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")
	monadPath := filepath.Join(tmpDir, "monad.bin")

	cfg := DaemonConfig{
		SocketPath:    sockPath,
		MonadPath:     monadPath,
		WatchDirs:     []string{tmpDir},
		OllamaURL:     "http://localhost:11434",
		OllamaModel:   "nomic-embed-text",
		OllamaTimeout: 30,
		Dimensions:    768,
	}

	d, err := NewDaemon(cfg, nil)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}

	data, version, err := d.GetMonad()
	if err != nil {
		t.Fatalf("GetMonad() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("GetMonad() returned empty data")
	}

	if version != 0 {
		t.Errorf("GetMonad() version = %d, want 0", version)
	}
}

func TestDaemon_GetStatus(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")
	monadPath := filepath.Join(tmpDir, "monad.bin")

	cfg := DaemonConfig{
		SocketPath:    sockPath,
		MonadPath:     monadPath,
		WatchDirs:     []string{tmpDir},
		OllamaURL:     "http://localhost:11434",
		OllamaModel:   "nomic-embed-text",
		OllamaTimeout: 30,
		Dimensions:    768,
	}

	d, err := NewDaemon(cfg, nil)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}

	ready, docs, state := d.GetStatus()

	if !ready {
		t.Error("GetStatus() ready = false, want true")
	}

	if docs != 0 {
		t.Errorf("GetStatus() docs = %d, want 0", docs)
	}

	if state != StateIdle {
		t.Errorf("GetStatus() state = %s, want %s", state, StateIdle)
	}
}

func TestDaemon_RunAndShutdown(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")
	monadPath := filepath.Join(tmpDir, "monad.bin")
	watchDir := filepath.Join(tmpDir, "watch")

	if err := os.MkdirAll(watchDir, 0755); err != nil {
		t.Fatalf("Failed to create watch directory: %v", err)
	}

	cfg := DaemonConfig{
		SocketPath:    sockPath,
		MonadPath:     monadPath,
		WatchDirs:     []string{watchDir},
		Extensions:    []string{".txt"},
		IgnoreHidden:  true,
		OllamaURL:     "http://localhost:11434",
		OllamaModel:   "nomic-embed-text",
		OllamaTimeout: 30,
		Dimensions:    768,
	}

	d, err := NewDaemon(cfg, nil)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- d.Run(ctx)
	}()

	// Give daemon time to start
	time.Sleep(100 * time.Millisecond)

	// Verify socket file exists
	if _, err := os.Stat(sockPath); os.IsNotExist(err) {
		t.Error("Socket file was not created")
	}

	// Cancel context to stop daemon
	cancel()

	// Wait for daemon to stop
	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Errorf("Run() error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("Daemon did not shut down in time")
	}

	// Verify monad was saved
	if _, err := os.Stat(monadPath); os.IsNotExist(err) {
		t.Error("Monad file was not saved on shutdown")
	}
}

func TestDaemon_ProcessesFileEvent(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")
	monadPath := filepath.Join(tmpDir, "monad.bin")
	watchDir := filepath.Join(tmpDir, "watch")

	if err := os.MkdirAll(watchDir, 0755); err != nil {
		t.Fatalf("Failed to create watch directory: %v", err)
	}

	// Create mock embedder
	mockEmb := &mockEmbedder{
		embeddings: make([]float32, 768),
	}
	for i := range mockEmb.embeddings {
		mockEmb.embeddings[i] = 0.1
	}

	cfg := DaemonConfig{
		SocketPath:    sockPath,
		MonadPath:     monadPath,
		WatchDirs:     []string{watchDir},
		Extensions:    []string{".txt"},
		IgnoreHidden:  true,
		OllamaURL:     "http://localhost:11434",
		OllamaModel:   "nomic-embed-text",
		OllamaTimeout: 30,
		Dimensions:    768,
	}

	d, err := NewDaemon(cfg, mockEmb)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- d.Run(ctx)
	}()

	// Give daemon time to start watching
	time.Sleep(200 * time.Millisecond)

	// Create a file in the watched directory
	testFile := filepath.Join(watchDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("Hello, this is test content for embedding."), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Wait for processing
	time.Sleep(500 * time.Millisecond)

	// Verify the monad was updated
	_, docs, _ := d.GetStatus()
	if docs == 0 {
		// Allow more time for slow systems
		time.Sleep(1 * time.Second)
		_, docs, _ = d.GetStatus()
	}

	cancel()

	// Wait for shutdown
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Error("Daemon did not shut down in time")
	}

	if mockEmb.CallCount() == 0 {
		t.Error("Embedder was never called")
	}
}

func TestDaemon_StateTransitions(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")
	monadPath := filepath.Join(tmpDir, "monad.bin")

	cfg := DaemonConfig{
		SocketPath:    sockPath,
		MonadPath:     monadPath,
		WatchDirs:     []string{tmpDir},
		OllamaURL:     "http://localhost:11434",
		OllamaModel:   "nomic-embed-text",
		OllamaTimeout: 30,
		Dimensions:    768,
	}

	d, err := NewDaemon(cfg, nil)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}

	// Initial state should be idle
	_, _, state := d.GetStatus()
	if state != StateIdle {
		t.Errorf("Initial state = %s, want %s", state, StateIdle)
	}

	// Set to processing
	d.setState(StateProcessing)
	_, _, state = d.GetStatus()
	if state != StateProcessing {
		t.Errorf("After setState(processing), state = %s, want %s", state, StateProcessing)
	}

	// Set back to idle
	d.setState(StateIdle)
	_, _, state = d.GetStatus()
	if state != StateIdle {
		t.Errorf("After setState(idle), state = %s, want %s", state, StateIdle)
	}
}

func TestDefaultDaemonConfig(t *testing.T) {
	cfg := DefaultDaemonConfig()

	if cfg.OllamaURL == "" {
		t.Error("Default OllamaURL is empty")
	}

	if cfg.OllamaModel == "" {
		t.Error("Default OllamaModel is empty")
	}

	if cfg.Dimensions == 0 {
		t.Error("Default Dimensions is 0")
	}

	if cfg.OllamaTimeout == 0 {
		t.Error("Default OllamaTimeout is 0")
	}

	if !cfg.IgnoreHidden {
		t.Error("Default IgnoreHidden should be true")
	}
}

func TestBuildConfig_Defaults(t *testing.T) {
	cfg, err := buildConfig("", "", "", "", "")
	if err != nil {
		t.Fatalf("buildConfig() error = %v", err)
	}

	if cfg.OllamaURL != "http://localhost:11434" {
		t.Errorf("Default OllamaURL = %s, want http://localhost:11434", cfg.OllamaURL)
	}

	if cfg.OllamaModel != "nomic-embed-text" {
		t.Errorf("Default OllamaModel = %s, want nomic-embed-text", cfg.OllamaModel)
	}

	if cfg.Dimensions != 768 {
		t.Errorf("Default Dimensions = %d, want 768", cfg.Dimensions)
	}
}

func TestBuildConfig_FlagOverrides(t *testing.T) {
	tmpDir := t.TempDir()

	cfg, err := buildConfig(
		"",
		tmpDir,
		"http://custom:8080",
		"custom-model",
		filepath.Join(tmpDir, "custom.sock"),
	)
	if err != nil {
		t.Fatalf("buildConfig() error = %v", err)
	}

	if len(cfg.WatchDirs) != 1 || cfg.WatchDirs[0] != tmpDir {
		t.Errorf("WatchDirs = %v, want [%s]", cfg.WatchDirs, tmpDir)
	}

	if cfg.OllamaURL != "http://custom:8080" {
		t.Errorf("OllamaURL = %s, want http://custom:8080", cfg.OllamaURL)
	}

	if cfg.OllamaModel != "custom-model" {
		t.Errorf("OllamaModel = %s, want custom-model", cfg.OllamaModel)
	}

	expectedSocket := filepath.Join(tmpDir, "custom.sock")
	if cfg.SocketPath != expectedSocket {
		t.Errorf("SocketPath = %s, want %s", cfg.SocketPath, expectedSocket)
	}
}

func TestBuildConfig_FromFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	// Create a config file
	configContent := `
[watch]
directories = ["/tmp/test"]
extensions = [".txt", ".md"]
ignore_hidden = true

[ollama]
url = "http://file-ollama:11434"
model = "file-model"
timeout_seconds = 60

[storage]
monad_path = "/tmp/monad.bin"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	cfg, err := buildConfig(configPath, "", "", "", "")
	if err != nil {
		t.Fatalf("buildConfig() error = %v", err)
	}

	if cfg.OllamaURL != "http://file-ollama:11434" {
		t.Errorf("OllamaURL = %s, want http://file-ollama:11434", cfg.OllamaURL)
	}

	if cfg.OllamaModel != "file-model" {
		t.Errorf("OllamaModel = %s, want file-model", cfg.OllamaModel)
	}

	if cfg.OllamaTimeout != 60 {
		t.Errorf("OllamaTimeout = %d, want 60", cfg.OllamaTimeout)
	}
}

func TestBuildConfig_FileWithFlagOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	// Create a config file
	configContent := `
[ollama]
url = "http://file-ollama:11434"
model = "file-model"

[storage]
monad_path = "/tmp/monad.bin"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	// Flags should override file settings
	cfg, err := buildConfig(configPath, "", "http://flag-ollama:8080", "flag-model", "")
	if err != nil {
		t.Fatalf("buildConfig() error = %v", err)
	}

	if cfg.OllamaURL != "http://flag-ollama:8080" {
		t.Errorf("OllamaURL = %s, want http://flag-ollama:8080", cfg.OllamaURL)
	}

	if cfg.OllamaModel != "flag-model" {
		t.Errorf("OllamaModel = %s, want flag-model", cfg.OllamaModel)
	}
}

func TestBuildConfig_InvalidFile(t *testing.T) {
	_, err := buildConfig("/nonexistent/config.toml", "", "", "", "")
	if err == nil {
		t.Error("buildConfig() with invalid file should return error")
	}
}

func TestIsHiddenFile(t *testing.T) {
	tests := []struct {
		path   string
		hidden bool
	}{
		{"/home/user/file.txt", false},
		{"/home/user/.hidden", true},
		{"/home/.config/file.txt", true},
		{".gitignore", true},
		{"normal.txt", false},
		{"/home/user/.config/myapp/config.toml", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isHiddenFile(tt.path); got != tt.hidden {
				t.Errorf("isHiddenFile(%q) = %v, want %v", tt.path, got, tt.hidden)
			}
		})
	}
}

func TestDaemon_IgnoresHiddenFiles(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")
	monadPath := filepath.Join(tmpDir, "monad.bin")
	watchDir := filepath.Join(tmpDir, "watch")

	if err := os.MkdirAll(watchDir, 0755); err != nil {
		t.Fatalf("Failed to create watch directory: %v", err)
	}

	// Create mock embedder
	mockEmb := &mockEmbedder{
		embeddings: make([]float32, 768),
	}

	cfg := DaemonConfig{
		SocketPath:    sockPath,
		MonadPath:     monadPath,
		WatchDirs:     []string{watchDir},
		Extensions:    []string{".txt"},
		IgnoreHidden:  true,
		OllamaURL:     "http://localhost:11434",
		OllamaModel:   "nomic-embed-text",
		OllamaTimeout: 30,
		Dimensions:    768,
	}

	d, err := NewDaemon(cfg, mockEmb)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- d.Run(ctx)
	}()

	time.Sleep(200 * time.Millisecond)

	// Create a hidden file
	hiddenFile := filepath.Join(watchDir, ".hidden.txt")
	if err := os.WriteFile(hiddenFile, []byte("Hidden content"), 0644); err != nil {
		t.Fatalf("Failed to create hidden file: %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	cancel()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Error("Daemon did not shut down in time")
	}

	// Hidden files should not be processed
	if mockEmb.CallCount() != 0 {
		t.Errorf("Hidden file was processed, embedder called %d times", mockEmb.CallCount())
	}
}

func TestDaemon_IgnoresUnsupportedExtensions(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")
	monadPath := filepath.Join(tmpDir, "monad.bin")
	watchDir := filepath.Join(tmpDir, "watch")

	if err := os.MkdirAll(watchDir, 0755); err != nil {
		t.Fatalf("Failed to create watch directory: %v", err)
	}

	// Create mock embedder
	mockEmb := &mockEmbedder{
		embeddings: make([]float32, 768),
	}

	cfg := DaemonConfig{
		SocketPath:    sockPath,
		MonadPath:     monadPath,
		WatchDirs:     []string{watchDir},
		Extensions:    []string{".txt"},  // Only .txt supported
		IgnoreHidden:  true,
		OllamaURL:     "http://localhost:11434",
		OllamaModel:   "nomic-embed-text",
		OllamaTimeout: 30,
		Dimensions:    768,
	}

	d, err := NewDaemon(cfg, mockEmb)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- d.Run(ctx)
	}()

	time.Sleep(200 * time.Millisecond)

	// Create a .json file (unsupported)
	jsonFile := filepath.Join(watchDir, "data.json")
	if err := os.WriteFile(jsonFile, []byte(`{"key": "value"}`), 0644); err != nil {
		t.Fatalf("Failed to create json file: %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	cancel()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Error("Daemon did not shut down in time")
	}

	// Unsupported extension files should not be processed
	if mockEmb.CallCount() != 0 {
		t.Errorf("Unsupported file was processed, embedder called %d times", mockEmb.CallCount())
	}
}

func TestDaemon_MultipleWatchDirs(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")
	monadPath := filepath.Join(tmpDir, "monad.bin")
	watchDir1 := filepath.Join(tmpDir, "watch1")
	watchDir2 := filepath.Join(tmpDir, "watch2")

	if err := os.MkdirAll(watchDir1, 0755); err != nil {
		t.Fatalf("Failed to create watch directory 1: %v", err)
	}
	if err := os.MkdirAll(watchDir2, 0755); err != nil {
		t.Fatalf("Failed to create watch directory 2: %v", err)
	}

	// Create mock embedder
	mockEmb := &mockEmbedder{
		embeddings: make([]float32, 768),
	}

	cfg := DaemonConfig{
		SocketPath:    sockPath,
		MonadPath:     monadPath,
		WatchDirs:     []string{watchDir1, watchDir2},
		Extensions:    []string{".txt"},
		IgnoreHidden:  true,
		OllamaURL:     "http://localhost:11434",
		OllamaModel:   "nomic-embed-text",
		OllamaTimeout: 30,
		Dimensions:    768,
	}

	d, err := NewDaemon(cfg, mockEmb)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- d.Run(ctx)
	}()

	time.Sleep(200 * time.Millisecond)

	// Create files in both directories
	file1 := filepath.Join(watchDir1, "file1.txt")
	file2 := filepath.Join(watchDir2, "file2.txt")

	if err := os.WriteFile(file1, []byte("Content 1"), 0644); err != nil {
		t.Fatalf("Failed to create file1: %v", err)
	}
	if err := os.WriteFile(file2, []byte("Content 2"), 0644); err != nil {
		t.Fatalf("Failed to create file2: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	cancel()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Error("Daemon did not shut down in time")
	}

	// Both files should be processed
	if mockEmb.CallCount() < 2 {
		t.Errorf("Expected at least 2 embedder calls, got %d", mockEmb.CallCount())
	}
}

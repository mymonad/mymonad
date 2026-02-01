// Package tests contains integration tests for the MyMonad system.
// These tests verify the complete pipeline from file watching through
// embedding generation to Monad updates.
package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mymonad/mymonad/internal/embed"
	"github.com/mymonad/mymonad/internal/ipc"
	"github.com/mymonad/mymonad/pkg/monad"
)

// mockOllamaServer creates a test HTTP server that mocks the Ollama API.
// It returns consistent embeddings for testing purposes.
func mockOllamaServer(t *testing.T, dimensions int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/embeddings" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Decode request to verify it's valid
		var req struct {
			Model  string `json:"model"`
			Prompt string `json:"prompt"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		// Generate deterministic embedding based on prompt length
		embedding := make([]float32, dimensions)
		seed := float32(len(req.Prompt)) / 100.0
		for i := range embedding {
			embedding[i] = seed + float32(i)*0.001
		}

		// Return embedding response
		resp := struct {
			Embedding []float32 `json:"embedding"`
		}{
			Embedding: embedding,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Logf("Failed to encode response: %v", err)
		}
	}))
}

// waitForSocket waits for a Unix socket file to exist.
func waitForSocket(t *testing.T, sockPath string, timeout time.Duration) bool {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sockPath); err == nil {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// waitForCondition polls a condition function until it returns true or timeout.
func waitForCondition(timeout time.Duration, condition func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// TestIntegration_IngestPipeline tests the complete ingest pipeline:
// file creation -> watcher detection -> embedding -> monad update -> IPC query.
func TestIntegration_IngestPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// 1. Create temp directories
	tmpDir := t.TempDir()
	watchDir := filepath.Join(tmpDir, "watch")
	dataDir := filepath.Join(tmpDir, "data")

	if err := os.MkdirAll(watchDir, 0755); err != nil {
		t.Fatalf("Failed to create watch directory: %v", err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatalf("Failed to create data directory: %v", err)
	}

	// 2. Start mock Ollama server
	const dimensions = 768
	mockOllama := mockOllamaServer(t, dimensions)
	defer mockOllama.Close()

	// 3. Create configuration
	socketPath := filepath.Join(dataDir, "ingest.sock")

	// 4. Create embedder pointing to mock server
	embedder := embed.NewOllamaClient(mockOllama.URL, "nomic-embed-text", 30)

	// 5. Create processor
	processor := embed.NewProcessor(embedder, 512)

	// 6. Create monad
	m := monad.New(dimensions)

	// 7. Create and start IPC server with a test provider
	provider := &testMonadProvider{
		monad: m,
		state: "idle",
	}

	server, err := ipc.NewServer(socketPath, provider)
	if err != nil {
		t.Fatalf("Failed to create IPC server: %v", err)
	}

	// Start server in goroutine
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		server.Start()
	}()
	defer func() {
		server.Stop()
		<-serverDone
	}()

	// 8. Wait for socket to be ready
	if !waitForSocket(t, socketPath, 2*time.Second) {
		t.Fatal("Socket file was not created within timeout")
	}

	// 9. Create test file and process it manually
	// (simulating what the daemon watcher would do)
	testFile := filepath.Join(watchDir, "test.txt")
	testContent := "This is test content for the integration test. It should be embedded and added to the monad."

	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// 10. Process the file (simulating daemon behavior)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	embedding, err := processor.ProcessFile(ctx, testFile)
	if err != nil {
		t.Fatalf("Failed to process file: %v", err)
	}

	// 11. Update the monad
	if err := m.Update(embedding); err != nil {
		t.Fatalf("Failed to update monad: %v", err)
	}

	// 12. Query daemon via IPC
	client, err := ipc.NewClient(socketPath)
	if err != nil {
		t.Fatalf("Failed to create IPC client: %v", err)
	}
	defer client.Close()

	// 13. Verify monad was updated via IPC
	monadData, version, err := client.GetMonad()
	if err != nil {
		t.Fatalf("GetMonad RPC failed: %v", err)
	}

	if version != 1 {
		t.Errorf("Expected version 1, got %d", version)
	}

	if len(monadData) == 0 {
		t.Error("GetMonad returned empty data")
	}

	// 14. Verify status
	ready, docsIndexed, state, err := client.Status()
	if err != nil {
		t.Fatalf("Status RPC failed: %v", err)
	}

	if !ready {
		t.Error("Expected daemon to be ready")
	}

	if docsIndexed != 1 {
		t.Errorf("Expected 1 document indexed, got %d", docsIndexed)
	}

	if state != "idle" {
		t.Errorf("Expected state 'idle', got '%s'", state)
	}

	// 15. Verify we can deserialize the monad
	receivedMonad := &monad.Monad{}
	if err := receivedMonad.UnmarshalBinary(monadData); err != nil {
		t.Fatalf("Failed to unmarshal monad: %v", err)
	}

	if receivedMonad.DocCount != 1 {
		t.Errorf("Expected DocCount 1, got %d", receivedMonad.DocCount)
	}

	if receivedMonad.Dimensions() != dimensions {
		t.Errorf("Expected %d dimensions, got %d", dimensions, receivedMonad.Dimensions())
	}
}

// TestIntegration_MultipleFiles tests processing multiple files.
func TestIntegration_MultipleFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	watchDir := filepath.Join(tmpDir, "watch")
	dataDir := filepath.Join(tmpDir, "data")

	if err := os.MkdirAll(watchDir, 0755); err != nil {
		t.Fatalf("Failed to create watch directory: %v", err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatalf("Failed to create data directory: %v", err)
	}

	const dimensions = 768
	mockOllama := mockOllamaServer(t, dimensions)
	defer mockOllama.Close()

	socketPath := filepath.Join(dataDir, "ingest.sock")

	embedder := embed.NewOllamaClient(mockOllama.URL, "nomic-embed-text", 30)
	processor := embed.NewProcessor(embedder, 512)
	m := monad.New(dimensions)

	provider := &testMonadProvider{
		monad: m,
		state: "idle",
	}

	server, err := ipc.NewServer(socketPath, provider)
	if err != nil {
		t.Fatalf("Failed to create IPC server: %v", err)
	}

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		server.Start()
	}()
	defer func() {
		server.Stop()
		<-serverDone
	}()

	if !waitForSocket(t, socketPath, 2*time.Second) {
		t.Fatal("Socket file was not created within timeout")
	}

	// Create and process multiple files
	testFiles := []struct {
		name    string
		content string
	}{
		{"file1.txt", "First file with some content about technology."},
		{"file2.txt", "Second file discussing different topics entirely."},
		{"file3.md", "# Markdown File\n\nWith structured content and headers."},
	}

	ctx := context.Background()

	for _, tf := range testFiles {
		filePath := filepath.Join(watchDir, tf.name)
		if err := os.WriteFile(filePath, []byte(tf.content), 0644); err != nil {
			t.Fatalf("Failed to create %s: %v", tf.name, err)
		}

		embedding, err := processor.ProcessFile(ctx, filePath)
		if err != nil {
			t.Fatalf("Failed to process %s: %v", tf.name, err)
		}

		if err := m.Update(embedding); err != nil {
			t.Fatalf("Failed to update monad with %s: %v", tf.name, err)
		}
	}

	// Verify via IPC
	client, err := ipc.NewClient(socketPath)
	if err != nil {
		t.Fatalf("Failed to create IPC client: %v", err)
	}
	defer client.Close()

	_, version, err := client.GetMonad()
	if err != nil {
		t.Fatalf("GetMonad failed: %v", err)
	}

	expectedVersion := int64(len(testFiles))
	if version != expectedVersion {
		t.Errorf("Expected version %d, got %d", expectedVersion, version)
	}

	_, docsIndexed, _, err := client.Status()
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}

	if docsIndexed != int64(len(testFiles)) {
		t.Errorf("Expected %d documents indexed, got %d", len(testFiles), docsIndexed)
	}
}

// TestIntegration_MonadPersistence tests saving and loading monad data.
func TestIntegration_MonadPersistence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	monadPath := filepath.Join(tmpDir, "monad.bin")

	const dimensions = 768
	mockOllama := mockOllamaServer(t, dimensions)
	defer mockOllama.Close()

	embedder := embed.NewOllamaClient(mockOllama.URL, "nomic-embed-text", 30)
	processor := embed.NewProcessor(embedder, 512)

	// Create initial monad and update it
	m := monad.New(dimensions)

	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("Persistence test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	ctx := context.Background()
	embedding, err := processor.ProcessFile(ctx, testFile)
	if err != nil {
		t.Fatalf("Failed to process file: %v", err)
	}

	if err := m.Update(embedding); err != nil {
		t.Fatalf("Failed to update monad: %v", err)
	}

	// Save monad
	if err := monad.SaveToFile(m, monadPath); err != nil {
		t.Fatalf("Failed to save monad: %v", err)
	}

	// Load monad and verify
	loaded, err := monad.LoadFromFile(monadPath)
	if err != nil {
		t.Fatalf("Failed to load monad: %v", err)
	}

	if loaded.Version != m.Version {
		t.Errorf("Version mismatch: got %d, want %d", loaded.Version, m.Version)
	}

	if loaded.DocCount != m.DocCount {
		t.Errorf("DocCount mismatch: got %d, want %d", loaded.DocCount, m.DocCount)
	}

	if loaded.Dimensions() != m.Dimensions() {
		t.Errorf("Dimensions mismatch: got %d, want %d", loaded.Dimensions(), m.Dimensions())
	}

	// Verify vectors match
	similarity := m.CosineSimilarity(loaded)
	if similarity < 0.9999 {
		t.Errorf("Loaded monad vector differs from original, similarity: %f", similarity)
	}
}

// TestIntegration_ConcurrentUpdates tests thread-safe monad updates.
func TestIntegration_ConcurrentUpdates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()

	const dimensions = 768
	mockOllama := mockOllamaServer(t, dimensions)
	defer mockOllama.Close()

	embedder := embed.NewOllamaClient(mockOllama.URL, "nomic-embed-text", 30)
	processor := embed.NewProcessor(embedder, 512)
	m := monad.New(dimensions)

	const numFiles = 10
	var wg sync.WaitGroup

	// Create test files
	for i := 0; i < numFiles; i++ {
		filePath := filepath.Join(tmpDir, filepath.Base(t.Name())+string(rune('a'+i))+".txt")
		content := []byte("Concurrent test file content " + string(rune('0'+i)))
		if err := os.WriteFile(filePath, content, 0644); err != nil {
			t.Fatalf("Failed to create file %d: %v", i, err)
		}

		wg.Add(1)
		go func(path string) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			embedding, err := processor.ProcessFile(ctx, path)
			if err != nil {
				t.Errorf("Failed to process %s: %v", path, err)
				return
			}

			if err := m.Update(embedding); err != nil {
				t.Errorf("Failed to update monad: %v", err)
			}
		}(filePath)
	}

	wg.Wait()

	if m.DocCount != numFiles {
		t.Errorf("Expected DocCount %d, got %d", numFiles, m.DocCount)
	}

	if m.Version != int64(numFiles) {
		t.Errorf("Expected Version %d, got %d", numFiles, m.Version)
	}
}

// TestIntegration_IPCClientRetry tests IPC client behavior with connection issues.
func TestIntegration_IPCClientRetry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Try to connect before server starts - should fail
	_, err := ipc.NewClient(socketPath)
	if err != nil {
		// Connection might fail immediately or lazily
		// Both are acceptable behaviors
		t.Logf("Connection before server: %v", err)
	}

	// Start server
	m := monad.New(768)
	provider := &testMonadProvider{monad: m, state: "idle"}

	server, err := ipc.NewServer(socketPath, provider)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		server.Start()
	}()
	defer func() {
		server.Stop()
		<-serverDone
	}()

	if !waitForSocket(t, socketPath, 2*time.Second) {
		t.Fatal("Socket not ready")
	}

	// Now connection should work
	client, err := ipc.NewClient(socketPath)
	if err != nil {
		t.Fatalf("Failed to create client after server started: %v", err)
	}
	defer client.Close()

	ready, _, _, err := client.Status()
	if err != nil {
		t.Fatalf("Status call failed: %v", err)
	}

	if !ready {
		t.Error("Expected ready=true")
	}
}

// TestIntegration_UnsupportedFileTypes tests that unsupported files are rejected.
func TestIntegration_UnsupportedFileTypes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()

	const dimensions = 768
	mockOllama := mockOllamaServer(t, dimensions)
	defer mockOllama.Close()

	embedder := embed.NewOllamaClient(mockOllama.URL, "nomic-embed-text", 30)
	processor := embed.NewProcessor(embedder, 512)

	unsupportedFiles := []string{
		"test.json",
		"test.xml",
		"test.go",
		"test.py",
		"test.jpg",
	}

	ctx := context.Background()

	for _, filename := range unsupportedFiles {
		filePath := filepath.Join(tmpDir, filename)
		if err := os.WriteFile(filePath, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create %s: %v", filename, err)
		}

		_, err := processor.ProcessFile(ctx, filePath)
		if err != embed.ErrUnsupportedFormat {
			t.Errorf("Expected ErrUnsupportedFormat for %s, got: %v", filename, err)
		}
	}
}

// TestIntegration_EmptyFile tests that empty files are handled correctly.
func TestIntegration_EmptyFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()

	const dimensions = 768
	mockOllama := mockOllamaServer(t, dimensions)
	defer mockOllama.Close()

	embedder := embed.NewOllamaClient(mockOllama.URL, "nomic-embed-text", 30)
	processor := embed.NewProcessor(embedder, 512)

	// Test truly empty file
	emptyFile := filepath.Join(tmpDir, "empty.txt")
	if err := os.WriteFile(emptyFile, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to create empty file: %v", err)
	}

	ctx := context.Background()
	_, err := processor.ProcessFile(ctx, emptyFile)
	if err != embed.ErrEmptyFile {
		t.Errorf("Expected ErrEmptyFile for empty file, got: %v", err)
	}

	// Test whitespace-only file
	whitespaceFile := filepath.Join(tmpDir, "whitespace.txt")
	if err := os.WriteFile(whitespaceFile, []byte("   \n\t\n   "), 0644); err != nil {
		t.Fatalf("Failed to create whitespace file: %v", err)
	}

	_, err = processor.ProcessFile(ctx, whitespaceFile)
	if err != embed.ErrEmptyFile {
		t.Errorf("Expected ErrEmptyFile for whitespace-only file, got: %v", err)
	}
}

// TestIntegration_LargeFile tests processing a large file that requires chunking.
func TestIntegration_LargeFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()

	const dimensions = 768
	mockOllama := mockOllamaServer(t, dimensions)
	defer mockOllama.Close()

	embedder := embed.NewOllamaClient(mockOllama.URL, "nomic-embed-text", 30)
	processor := embed.NewProcessor(embedder, 512) // Small max tokens to force chunking

	m := monad.New(dimensions)

	// Create a large file that will require multiple chunks
	largeContent := ""
	for i := 0; i < 100; i++ {
		largeContent += "This is paragraph " + string(rune('0'+i%10)) + " of the large test file. "
		largeContent += "It contains enough text to require chunking when processed. "
		largeContent += "The processor should handle this gracefully.\n\n"
	}

	largeFile := filepath.Join(tmpDir, "large.txt")
	if err := os.WriteFile(largeFile, []byte(largeContent), 0644); err != nil {
		t.Fatalf("Failed to create large file: %v", err)
	}

	ctx := context.Background()
	embedding, err := processor.ProcessFile(ctx, largeFile)
	if err != nil {
		t.Fatalf("Failed to process large file: %v", err)
	}

	if len(embedding) != dimensions {
		t.Errorf("Expected %d dimensions, got %d", dimensions, len(embedding))
	}

	if err := m.Update(embedding); err != nil {
		t.Fatalf("Failed to update monad: %v", err)
	}

	if m.DocCount != 1 {
		t.Errorf("Expected DocCount 1, got %d", m.DocCount)
	}
}

// testMonadProvider implements ipc.MonadProvider for testing.
type testMonadProvider struct {
	monad *monad.Monad
	state string
	mu    sync.RWMutex
}

func (p *testMonadProvider) GetMonad() ([]byte, int64, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	data, err := p.monad.MarshalBinary()
	if err != nil {
		return nil, 0, err
	}
	return data, p.monad.Version, nil
}

func (p *testMonadProvider) GetStatus() (ready bool, docsIndexed int64, state string) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return true, p.monad.DocCount, p.state
}

func (p *testMonadProvider) SetState(state string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state = state
}

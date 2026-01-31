# Application Binaries Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement functional mymonad-ingest, mymonad-agent, and mymonad-cli binaries with real Ollama embeddings, multi-source P2P discovery, and IPC communication.

**Architecture:** Three binaries communicating via Unix socket gRPC. Ingest daemon watches files and calls Ollama for embeddings. Agent daemon runs libp2p with DNSADDR/user bootstrap discovery. CLI queries both via IPC.

**Tech Stack:** Go 1.21+, libp2p, Ollama API, gRPC, TOML (pelletier/go-toml), structured logging (log/slog)

---

## Task 1: Config Package - Core Types

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`

**Step 1: Write the failing test**

```go
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
```

**Step 2: Run test to verify it fails**

Run: `go test -v ./internal/config/...`
Expected: FAIL - package does not exist

**Step 3: Write minimal implementation**

```go
// internal/config/config.go
package config

import (
	"os"
	"path/filepath"
	"strings"
)

// Paths holds XDG-compliant paths for MyMonad.
type Paths struct {
	ConfigDir    string // ~/.config/mymonad
	DataDir      string // ~/.local/share/mymonad
	IngestSocket string // ~/.local/share/mymonad/ingest.sock
	AgentSocket  string // ~/.local/share/mymonad/agent.sock
	IdentityPath string // ~/.local/share/mymonad/identity.key
	MonadPath    string // ~/.local/share/mymonad/monad.bin
	PeersCache   string // ~/.local/share/mymonad/peers.json
}

// ExpandPath expands ~ to the user's home directory.
func ExpandPath(path string) string {
	if path == "~" {
		home, _ := os.UserHomeDir()
		return home
	}
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[2:])
	}
	return path
}

// DefaultPaths returns the default XDG-compliant paths.
func DefaultPaths() Paths {
	home, _ := os.UserHomeDir()
	configDir := filepath.Join(home, ".config", "mymonad")
	dataDir := filepath.Join(home, ".local", "share", "mymonad")

	return Paths{
		ConfigDir:    configDir,
		DataDir:      dataDir,
		IngestSocket: filepath.Join(dataDir, "ingest.sock"),
		AgentSocket:  filepath.Join(dataDir, "agent.sock"),
		IdentityPath: filepath.Join(dataDir, "identity.key"),
		MonadPath:    filepath.Join(dataDir, "monad.bin"),
		PeersCache:   filepath.Join(dataDir, "peers.json"),
	}
}

// EnsureDirectories creates config and data directories if they don't exist.
func (p Paths) EnsureDirectories() error {
	if err := os.MkdirAll(p.ConfigDir, 0700); err != nil {
		return err
	}
	return os.MkdirAll(p.DataDir, 0700)
}
```

**Step 4: Run test to verify it passes**

Run: `go test -v ./internal/config/...`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/config/
git commit -m "[Feat][Config] Add path expansion and XDG defaults"
```

---

## Task 2: Config Package - TOML Parsing

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `go.mod` (add dependency)

**Step 1: Add TOML dependency**

Run: `go get github.com/pelletier/go-toml/v2`

**Step 2: Write the failing test**

```go
// Add to internal/config/config_test.go

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
```

**Step 3: Run test to verify it fails**

Run: `go test -v ./internal/config/...`
Expected: FAIL - LoadIngestConfig undefined

**Step 4: Write minimal implementation**

```go
// Add to internal/config/config.go

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// IngestConfig holds configuration for mymonad-ingest.
type IngestConfig struct {
	Watch   WatchConfig   `toml:"watch"`
	Ollama  OllamaConfig  `toml:"ollama"`
	Storage StorageConfig `toml:"storage"`
}

// WatchConfig holds file watching settings.
type WatchConfig struct {
	Directories  []string `toml:"directories"`
	Extensions   []string `toml:"extensions"`
	IgnoreHidden bool     `toml:"ignore_hidden"`
}

// OllamaConfig holds Ollama API settings.
type OllamaConfig struct {
	URL            string `toml:"url"`
	Model          string `toml:"model"`
	TimeoutSeconds int    `toml:"timeout_seconds"`
}

// StorageConfig holds storage paths.
type StorageConfig struct {
	MonadPath string `toml:"monad_path"`
}

// AgentConfig holds configuration for mymonad-agent.
type AgentConfig struct {
	Network   NetworkConfig   `toml:"network"`
	Discovery DiscoveryConfig `toml:"discovery"`
	Protocol  ProtocolConfig  `toml:"protocol"`
	Storage   AgentStorage    `toml:"storage"`
}

// NetworkConfig holds P2P network settings.
type NetworkConfig struct {
	Port       int    `toml:"port"`
	ExternalIP string `toml:"external_ip"`
}

// DiscoveryConfig holds peer discovery settings.
type DiscoveryConfig struct {
	DNSSeeds    []string `toml:"dns_seeds"`
	Bootstrap   []string `toml:"bootstrap"`
	MDNSEnabled bool     `toml:"mdns_enabled"`
}

// ProtocolConfig holds protocol parameters.
type ProtocolConfig struct {
	SimilarityThreshold float64 `toml:"similarity_threshold"`
	ChallengeDifficulty int     `toml:"challenge_difficulty"`
}

// AgentStorage holds agent storage paths.
type AgentStorage struct {
	IdentityPath string `toml:"identity_path"`
	PeersCache   string `toml:"peers_cache"`
}

// DefaultIngestConfig returns IngestConfig with sensible defaults.
func DefaultIngestConfig() IngestConfig {
	paths := DefaultPaths()
	home, _ := os.UserHomeDir()

	return IngestConfig{
		Watch: WatchConfig{
			Directories:  []string{filepath.Join(home, "Documents")},
			Extensions:   []string{".txt", ".md"},
			IgnoreHidden: true,
		},
		Ollama: OllamaConfig{
			URL:            "http://localhost:11434",
			Model:          "nomic-embed-text",
			TimeoutSeconds: 30,
		},
		Storage: StorageConfig{
			MonadPath: paths.MonadPath,
		},
	}
}

// DefaultAgentConfig returns AgentConfig with sensible defaults.
func DefaultAgentConfig() AgentConfig {
	paths := DefaultPaths()

	return AgentConfig{
		Network: NetworkConfig{
			Port:       0,
			ExternalIP: "",
		},
		Discovery: DiscoveryConfig{
			DNSSeeds:    []string{"_dnsaddr.bootstrap.mymonad.net"},
			Bootstrap:   []string{},
			MDNSEnabled: false,
		},
		Protocol: ProtocolConfig{
			SimilarityThreshold: 0.7,
			ChallengeDifficulty: 20,
		},
		Storage: AgentStorage{
			IdentityPath: paths.IdentityPath,
			PeersCache:   paths.PeersCache,
		},
	}
}

// LoadIngestConfig loads IngestConfig from a TOML file.
// Missing fields use defaults.
func LoadIngestConfig(path string) (IngestConfig, error) {
	cfg := DefaultIngestConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}

	if err := toml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}

	// Expand paths
	for i, dir := range cfg.Watch.Directories {
		cfg.Watch.Directories[i] = ExpandPath(dir)
	}
	cfg.Storage.MonadPath = ExpandPath(cfg.Storage.MonadPath)

	return cfg, nil
}

// LoadAgentConfig loads AgentConfig from a TOML file.
// Missing fields use defaults.
func LoadAgentConfig(path string) (AgentConfig, error) {
	cfg := DefaultAgentConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}

	if err := toml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}

	// Expand paths
	cfg.Storage.IdentityPath = ExpandPath(cfg.Storage.IdentityPath)
	cfg.Storage.PeersCache = ExpandPath(cfg.Storage.PeersCache)

	return cfg, nil
}
```

**Step 5: Run test to verify it passes**

Run: `go test -v ./internal/config/...`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/config/ go.mod go.sum
git commit -m "[Feat][Config] Add TOML config loading for ingest and agent"
```

---

## Task 3: Ollama Client

**Files:**
- Create: `internal/embed/ollama.go`
- Create: `internal/embed/ollama_test.go`

**Step 1: Write the failing test**

```go
// internal/embed/ollama_test.go
package embed

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOllamaClient_Embed(t *testing.T) {
	// Mock Ollama server
	expectedEmbedding := make([]float32, 768)
	for i := range expectedEmbedding {
		expectedEmbedding[i] = float32(i) * 0.001
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/embeddings" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}

		var req struct {
			Model  string `json:"model"`
			Prompt string `json:"prompt"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request: %v", err)
		}
		if req.Model != "nomic-embed-text" {
			t.Errorf("unexpected model: %s", req.Model)
		}

		// Convert to float64 for JSON
		embedding64 := make([]float64, len(expectedEmbedding))
		for i, v := range expectedEmbedding {
			embedding64[i] = float64(v)
		}

		resp := map[string]interface{}{
			"embedding": embedding64,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOllamaClient(server.URL, "nomic-embed-text", 30)
	embedding, err := client.Embed(context.Background(), "test text")
	if err != nil {
		t.Fatalf("Embed failed: %v", err)
	}

	if len(embedding) != 768 {
		t.Errorf("expected 768 dimensions, got %d", len(embedding))
	}
}

func TestOllamaClient_EmbedRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		embedding := make([]float64, 768)
		resp := map[string]interface{}{"embedding": embedding}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOllamaClient(server.URL, "nomic-embed-text", 5)
	_, err := client.Embed(context.Background(), "test")
	if err != nil {
		t.Fatalf("Embed should succeed after retries: %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestOllamaClient_EmbedTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never respond
		select {}
	}))
	defer server.Close()

	client := NewOllamaClient(server.URL, "nomic-embed-text", 1)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := client.Embed(ctx, "test")
	if err == nil {
		t.Error("expected timeout error")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v ./internal/embed/...`
Expected: FAIL - package does not exist

**Step 3: Write minimal implementation**

```go
// internal/embed/ollama.go
package embed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ErrOllamaUnavailable is returned when Ollama cannot be reached.
var ErrOllamaUnavailable = errors.New("ollama: service unavailable")

// OllamaClient communicates with an Ollama server for embeddings.
type OllamaClient struct {
	baseURL string
	model   string
	client  *http.Client
}

// NewOllamaClient creates a new Ollama client.
func NewOllamaClient(baseURL, model string, timeoutSeconds int) *OllamaClient {
	return &OllamaClient{
		baseURL: baseURL,
		model:   model,
		client: &http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		},
	}
}

type embeddingRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

type embeddingResponse struct {
	Embedding []float64 `json:"embedding"`
}

// Embed generates an embedding for the given text.
// Retries up to 3 times with exponential backoff on transient errors.
func (c *OllamaClient) Embed(ctx context.Context, text string) ([]float32, error) {
	var lastErr error

	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<attempt) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		embedding, err := c.doEmbed(ctx, text)
		if err == nil {
			return embedding, nil
		}

		lastErr = err
		if !isRetryable(err) {
			return nil, err
		}
	}

	return nil, lastErr
}

func (c *OllamaClient) doEmbed(ctx context.Context, text string) ([]float32, error) {
	reqBody := embeddingRequest{
		Model:  c.model,
		Prompt: text,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, ErrOllamaUnavailable
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var embResp embeddingResponse
	if err := json.NewDecoder(resp.Body).Decode(&embResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert float64 to float32
	result := make([]float32, len(embResp.Embedding))
	for i, v := range embResp.Embedding {
		result[i] = float32(v)
	}

	return result, nil
}

func isRetryable(err error) bool {
	return errors.Is(err, ErrOllamaUnavailable)
}
```

**Step 4: Add missing import to test and run**

Add `"time"` import to test file.

Run: `go test -v ./internal/embed/...`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/embed/
git commit -m "[Feat][Embed] Add Ollama client with retry logic"
```

---

## Task 4: Text Chunking

**Files:**
- Create: `internal/embed/chunker.go`
- Create: `internal/embed/chunker_test.go`

**Step 1: Write the failing test**

```go
// internal/embed/chunker_test.go
package embed

import (
	"strings"
	"testing"
)

func TestChunkText_SmallText(t *testing.T) {
	text := "This is a small text."
	chunks := ChunkText(text, 100)

	if len(chunks) != 1 {
		t.Errorf("expected 1 chunk, got %d", len(chunks))
	}
	if chunks[0] != text {
		t.Errorf("chunk should equal input")
	}
}

func TestChunkText_LargeText(t *testing.T) {
	// Create text with ~1000 words
	words := make([]string, 1000)
	for i := range words {
		words[i] = "word"
	}
	text := strings.Join(words, " ")

	chunks := ChunkText(text, 512) // ~512 tokens

	if len(chunks) < 2 {
		t.Errorf("expected multiple chunks, got %d", len(chunks))
	}

	// Verify no chunk exceeds limit (rough estimate: 1 token ≈ 4 chars)
	maxChars := 512 * 4
	for i, chunk := range chunks {
		if len(chunk) > maxChars+100 { // Allow some buffer
			t.Errorf("chunk %d exceeds max size: %d chars", i, len(chunk))
		}
	}
}

func TestChunkText_PreservesParagraphs(t *testing.T) {
	text := "First paragraph.\n\nSecond paragraph.\n\nThird paragraph."
	chunks := ChunkText(text, 100)

	// Should split on paragraph boundaries when possible
	for _, chunk := range chunks {
		if strings.Count(chunk, "\n\n") > 1 {
			t.Error("chunk should not span multiple paragraph breaks")
		}
	}
}

func TestChunkText_EmptyText(t *testing.T) {
	chunks := ChunkText("", 512)
	if len(chunks) != 0 {
		t.Errorf("expected 0 chunks for empty text, got %d", len(chunks))
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v ./internal/embed/... -run TestChunk`
Expected: FAIL - ChunkText undefined

**Step 3: Write minimal implementation**

```go
// internal/embed/chunker.go
package embed

import (
	"strings"
)

// ChunkText splits text into chunks of approximately maxTokens tokens.
// It tries to split on paragraph boundaries, then sentence boundaries.
// Rough estimate: 1 token ≈ 4 characters.
func ChunkText(text string, maxTokens int) []string {
	if text == "" {
		return nil
	}

	maxChars := maxTokens * 4

	// If text fits in one chunk, return as-is
	if len(text) <= maxChars {
		return []string{text}
	}

	var chunks []string

	// Split by double newlines (paragraphs)
	paragraphs := strings.Split(text, "\n\n")

	var currentChunk strings.Builder
	for _, para := range paragraphs {
		para = strings.TrimSpace(para)
		if para == "" {
			continue
		}

		// If adding this paragraph exceeds limit, flush current chunk
		if currentChunk.Len() > 0 && currentChunk.Len()+len(para)+2 > maxChars {
			chunks = append(chunks, strings.TrimSpace(currentChunk.String()))
			currentChunk.Reset()
		}

		// If single paragraph exceeds limit, split by sentences
		if len(para) > maxChars {
			if currentChunk.Len() > 0 {
				chunks = append(chunks, strings.TrimSpace(currentChunk.String()))
				currentChunk.Reset()
			}
			chunks = append(chunks, chunkBySentence(para, maxChars)...)
			continue
		}

		if currentChunk.Len() > 0 {
			currentChunk.WriteString("\n\n")
		}
		currentChunk.WriteString(para)
	}

	if currentChunk.Len() > 0 {
		chunks = append(chunks, strings.TrimSpace(currentChunk.String()))
	}

	return chunks
}

func chunkBySentence(text string, maxChars int) []string {
	var chunks []string
	var current strings.Builder

	// Simple sentence split on . ! ?
	sentences := splitSentences(text)

	for _, sent := range sentences {
		if current.Len()+len(sent) > maxChars && current.Len() > 0 {
			chunks = append(chunks, strings.TrimSpace(current.String()))
			current.Reset()
		}
		current.WriteString(sent)
	}

	if current.Len() > 0 {
		chunks = append(chunks, strings.TrimSpace(current.String()))
	}

	return chunks
}

func splitSentences(text string) []string {
	var sentences []string
	var current strings.Builder

	for i, r := range text {
		current.WriteRune(r)
		if r == '.' || r == '!' || r == '?' {
			// Check if followed by space or end of string
			if i+1 >= len(text) || text[i+1] == ' ' || text[i+1] == '\n' {
				sentences = append(sentences, current.String())
				current.Reset()
			}
		}
	}

	if current.Len() > 0 {
		sentences = append(sentences, current.String())
	}

	return sentences
}
```

**Step 4: Run test to verify it passes**

Run: `go test -v ./internal/embed/... -run TestChunk`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/embed/chunker.go internal/embed/chunker_test.go
git commit -m "[Feat][Embed] Add text chunking for embedding pipeline"
```

---

## Task 5: Document Processor

**Files:**
- Create: `internal/embed/processor.go`
- Create: `internal/embed/processor_test.go`

**Step 1: Write the failing test**

```go
// internal/embed/processor_test.go
package embed

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestProcessor_ProcessFile(t *testing.T) {
	// Create mock Ollama that returns predictable embeddings
	mockClient := &mockEmbedder{
		embedFunc: func(ctx context.Context, text string) ([]float32, error) {
			// Return embedding based on text length for predictability
			embedding := make([]float32, 768)
			embedding[0] = float32(len(text)) * 0.001
			return embedding, nil
		},
	}

	proc := NewProcessor(mockClient, 512)

	// Create temp file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	content := "This is test content for embedding."
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	embedding, err := proc.ProcessFile(context.Background(), tmpFile)
	if err != nil {
		t.Fatalf("ProcessFile failed: %v", err)
	}

	if len(embedding) != 768 {
		t.Errorf("expected 768 dimensions, got %d", len(embedding))
	}
}

func TestProcessor_ProcessFile_UnsupportedExtension(t *testing.T) {
	proc := NewProcessor(nil, 512)

	_, err := proc.ProcessFile(context.Background(), "/path/to/file.pdf")
	if err == nil {
		t.Error("expected error for unsupported extension")
	}
}

func TestProcessor_ProcessFile_EmptyFile(t *testing.T) {
	mockClient := &mockEmbedder{}
	proc := NewProcessor(mockClient, 512)

	tmpFile := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(tmpFile, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := proc.ProcessFile(context.Background(), tmpFile)
	if err == nil {
		t.Error("expected error for empty file")
	}
}

type mockEmbedder struct {
	embedFunc func(ctx context.Context, text string) ([]float32, error)
}

func (m *mockEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	if m.embedFunc != nil {
		return m.embedFunc(ctx, text)
	}
	return make([]float32, 768), nil
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v ./internal/embed/... -run TestProcessor`
Expected: FAIL - Processor undefined

**Step 3: Write minimal implementation**

```go
// internal/embed/processor.go
package embed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var (
	// ErrUnsupportedFormat is returned for unsupported file types.
	ErrUnsupportedFormat = errors.New("embed: unsupported file format")
	// ErrEmptyFile is returned when a file has no content.
	ErrEmptyFile = errors.New("embed: file is empty")
)

// SupportedExtensions lists file types that can be processed.
var SupportedExtensions = map[string]bool{
	".txt": true,
	".md":  true,
}

// Embedder generates embeddings from text.
type Embedder interface {
	Embed(ctx context.Context, text string) ([]float32, error)
}

// Processor handles file reading, chunking, and embedding.
type Processor struct {
	embedder  Embedder
	maxTokens int
}

// NewProcessor creates a new document processor.
func NewProcessor(embedder Embedder, maxTokens int) *Processor {
	return &Processor{
		embedder:  embedder,
		maxTokens: maxTokens,
	}
}

// ProcessFile reads a file, chunks it, embeds each chunk, and returns the average.
func (p *Processor) ProcessFile(ctx context.Context, path string) ([]float32, error) {
	ext := strings.ToLower(filepath.Ext(path))
	if !SupportedExtensions[ext] {
		return nil, ErrUnsupportedFormat
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	text := strings.TrimSpace(string(content))
	if text == "" {
		return nil, ErrEmptyFile
	}

	chunks := ChunkText(text, p.maxTokens)
	if len(chunks) == 0 {
		return nil, ErrEmptyFile
	}

	// Embed each chunk
	var embeddings [][]float32
	for _, chunk := range chunks {
		embedding, err := p.embedder.Embed(ctx, chunk)
		if err != nil {
			return nil, err
		}
		embeddings = append(embeddings, embedding)
	}

	// Average all chunk embeddings
	return averageEmbeddings(embeddings), nil
}

// averageEmbeddings computes the element-wise average of multiple embeddings.
func averageEmbeddings(embeddings [][]float32) []float32 {
	if len(embeddings) == 0 {
		return nil
	}
	if len(embeddings) == 1 {
		return embeddings[0]
	}

	dims := len(embeddings[0])
	result := make([]float32, dims)

	for _, emb := range embeddings {
		for i, v := range emb {
			result[i] += v
		}
	}

	n := float32(len(embeddings))
	for i := range result {
		result[i] /= n
	}

	return result
}
```

**Step 4: Run test to verify it passes**

Run: `go test -v ./internal/embed/... -run TestProcessor`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/embed/processor.go internal/embed/processor_test.go
git commit -m "[Feat][Embed] Add document processor with chunking and averaging"
```

---

## Task 6: DNSADDR Discovery

**Files:**
- Create: `internal/discovery/dnsaddr.go`
- Create: `internal/discovery/dnsaddr_test.go`

**Step 1: Write the failing test**

```go
// internal/discovery/dnsaddr_test.go
package discovery

import (
	"context"
	"testing"
)

func TestParseDNSADDR(t *testing.T) {
	tests := []struct {
		input   string
		valid   bool
		hasAddr bool
	}{
		{"dnsaddr=/dns4/node.example.com/tcp/4001/p2p/12D3KooWTest", true, true},
		{"dnsaddr=/ip4/192.168.1.1/tcp/4001/p2p/12D3KooWTest", true, true},
		{"invalid", false, false},
		{"dnsaddr=", false, false},
	}

	for _, tt := range tests {
		addr, err := ParseDNSADDR(tt.input)
		if tt.valid {
			if err != nil {
				t.Errorf("ParseDNSADDR(%q) unexpected error: %v", tt.input, err)
			}
			if tt.hasAddr && addr == nil {
				t.Errorf("ParseDNSADDR(%q) returned nil addr", tt.input)
			}
		} else {
			if err == nil {
				t.Errorf("ParseDNSADDR(%q) expected error", tt.input)
			}
		}
	}
}

func TestDNSADDRResolver_ParseRecords(t *testing.T) {
	records := []string{
		"dnsaddr=/dns4/node1.mymonad.net/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
		"dnsaddr=/dns4/node2.mymonad.net/tcp/4001/p2p/12D3KooWGhufNRcqaKvALxQjMNcJNhU9paxRwpJvdNbcwzYyRrW2",
		"invalid-record",
	}

	resolver := &DNSADDRResolver{}
	addrs := resolver.parseRecords(records)

	if len(addrs) != 2 {
		t.Errorf("expected 2 valid addrs, got %d", len(addrs))
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v ./internal/discovery/...`
Expected: FAIL - package does not exist

**Step 3: Write minimal implementation**

```go
// internal/discovery/dnsaddr.go
package discovery

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/multiformats/go-multiaddr"
)

var (
	// ErrInvalidDNSADDR is returned for malformed DNSADDR records.
	ErrInvalidDNSADDR = errors.New("discovery: invalid DNSADDR record")
	// ErrNoRecords is returned when DNS lookup returns no records.
	ErrNoRecords = errors.New("discovery: no DNSADDR records found")
)

// DNSADDRResolver resolves DNSADDR TXT records to multiaddrs.
type DNSADDRResolver struct {
	timeout time.Duration
}

// NewDNSADDRResolver creates a resolver with the given timeout.
func NewDNSADDRResolver(timeout time.Duration) *DNSADDRResolver {
	return &DNSADDRResolver{timeout: timeout}
}

// Resolve queries DNS TXT records and returns peer multiaddrs.
func (r *DNSADDRResolver) Resolve(ctx context.Context, dnsaddr string) ([]multiaddr.Multiaddr, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Query TXT records
	records, err := net.DefaultResolver.LookupTXT(ctx, dnsaddr)
	if err != nil {
		return nil, err
	}

	addrs := r.parseRecords(records)
	if len(addrs) == 0 {
		return nil, ErrNoRecords
	}

	// Shuffle to distribute load
	rand.Shuffle(len(addrs), func(i, j int) {
		addrs[i], addrs[j] = addrs[j], addrs[i]
	})

	return addrs, nil
}

// parseRecords extracts multiaddrs from DNSADDR TXT records.
func (r *DNSADDRResolver) parseRecords(records []string) []multiaddr.Multiaddr {
	var addrs []multiaddr.Multiaddr

	for _, record := range records {
		addr, err := ParseDNSADDR(record)
		if err != nil {
			continue
		}
		addrs = append(addrs, addr)
	}

	return addrs
}

// ParseDNSADDR parses a single DNSADDR TXT record.
// Format: dnsaddr=/dns4/host/tcp/port/p2p/peerID
func ParseDNSADDR(record string) (multiaddr.Multiaddr, error) {
	const prefix = "dnsaddr="
	if !strings.HasPrefix(record, prefix) {
		return nil, ErrInvalidDNSADDR
	}

	addrStr := strings.TrimPrefix(record, prefix)
	if addrStr == "" {
		return nil, ErrInvalidDNSADDR
	}

	addr, err := multiaddr.NewMultiaddr(addrStr)
	if err != nil {
		return nil, ErrInvalidDNSADDR
	}

	return addr, nil
}

// ResolveMultiple resolves multiple DNS seeds in parallel.
func (r *DNSADDRResolver) ResolveMultiple(ctx context.Context, seeds []string) []multiaddr.Multiaddr {
	type result struct {
		addrs []multiaddr.Multiaddr
	}

	results := make(chan result, len(seeds))

	for _, seed := range seeds {
		go func(s string) {
			addrs, _ := r.Resolve(ctx, s)
			results <- result{addrs: addrs}
		}(seed)
	}

	var allAddrs []multiaddr.Multiaddr
	for i := 0; i < len(seeds); i++ {
		r := <-results
		allAddrs = append(allAddrs, r.addrs...)
	}

	return allAddrs
}
```

**Step 4: Run test to verify it passes**

Run: `go test -v ./internal/discovery/...`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/discovery/
git commit -m "[Feat][Discovery] Add DNSADDR resolver for bootstrap peers"
```

---

## Task 7: Multi-Source Discovery Manager

**Files:**
- Create: `internal/discovery/manager.go`
- Create: `internal/discovery/manager_test.go`

**Step 1: Write the failing test**

```go
// internal/discovery/manager_test.go
package discovery

import (
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func TestManager_ParseBootstrapAddrs(t *testing.T) {
	mgr := &Manager{}

	addrs := []string{
		"/ip4/192.168.1.1/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
		"/dns4/node.example.com/tcp/4001/p2p/12D3KooWGhufNRcqaKvALxQjMNcJNhU9paxRwpJvdNbcwzYyRrW2",
		"invalid-addr",
	}

	peers := mgr.parseBootstrapAddrs(addrs)
	if len(peers) != 2 {
		t.Errorf("expected 2 valid peers, got %d", len(peers))
	}
}

func TestManager_DiscoverySources(t *testing.T) {
	cfg := ManagerConfig{
		DNSSeeds:    []string{"_dnsaddr.test.mymonad.net"},
		Bootstrap:   []string{"/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"},
		MDNSEnabled: false,
	}

	mgr := NewManager(cfg)

	if len(mgr.config.DNSSeeds) != 1 {
		t.Errorf("expected 1 DNS seed")
	}
	if len(mgr.config.Bootstrap) != 1 {
		t.Errorf("expected 1 bootstrap addr")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v ./internal/discovery/... -run TestManager`
Expected: FAIL - Manager undefined

**Step 3: Write minimal implementation**

```go
// internal/discovery/manager.go
package discovery

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// ManagerConfig holds discovery configuration.
type ManagerConfig struct {
	DNSSeeds    []string
	Bootstrap   []string
	MDNSEnabled bool
	DNSTimeout  time.Duration
}

// Manager coordinates multiple discovery sources.
type Manager struct {
	config   ManagerConfig
	resolver *DNSADDRResolver
}

// NewManager creates a discovery manager.
func NewManager(cfg ManagerConfig) *Manager {
	if cfg.DNSTimeout == 0 {
		cfg.DNSTimeout = 5 * time.Second
	}

	return &Manager{
		config:   cfg,
		resolver: NewDNSADDRResolver(cfg.DNSTimeout),
	}
}

// DiscoverPeers returns peers from all configured sources.
// Priority: user-defined bootstrap > DNSADDR > mDNS
func (m *Manager) DiscoverPeers(ctx context.Context) []peer.AddrInfo {
	var allPeers []peer.AddrInfo
	seen := make(map[peer.ID]bool)

	// 1. User-defined bootstrap (highest priority)
	for _, pi := range m.parseBootstrapAddrs(m.config.Bootstrap) {
		if !seen[pi.ID] {
			allPeers = append(allPeers, pi)
			seen[pi.ID] = true
		}
	}

	// 2. DNSADDR seeds
	if len(m.config.DNSSeeds) > 0 {
		addrs := m.resolver.ResolveMultiple(ctx, m.config.DNSSeeds)
		for _, addr := range addrs {
			pi, err := peer.AddrInfoFromP2pAddr(addr)
			if err != nil {
				continue
			}
			if !seen[pi.ID] {
				allPeers = append(allPeers, *pi)
				seen[pi.ID] = true
			}
		}
	}

	// 3. mDNS handled separately by libp2p if enabled

	return allPeers
}

// parseBootstrapAddrs converts multiaddr strings to peer.AddrInfo.
func (m *Manager) parseBootstrapAddrs(addrs []string) []peer.AddrInfo {
	var peers []peer.AddrInfo

	for _, addrStr := range addrs {
		ma, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			continue
		}

		pi, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			continue
		}

		peers = append(peers, *pi)
	}

	return peers
}

// Config returns the manager's configuration.
func (m *Manager) Config() ManagerConfig {
	return m.config
}
```

**Step 4: Run test to verify it passes**

Run: `go test -v ./internal/discovery/... -run TestManager`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/discovery/manager.go internal/discovery/manager_test.go
git commit -m "[Feat][Discovery] Add multi-source discovery manager"
```

---

## Task 8: Agent Proto - Add Agent Service

**Files:**
- Modify: `api/proto/monad.proto`
- Run: protoc to regenerate

**Step 1: Update proto file**

```protobuf
// api/proto/monad.proto - add after MonadStore service

// AgentService is the IPC service exposed by the Agent Daemon.
service AgentService {
  // Status returns the agent's current status.
  rpc Status(AgentStatusRequest) returns (AgentStatusResponse);

  // Peers returns connected peers.
  rpc Peers(PeersRequest) returns (PeersResponse);

  // Bootstrap manually connects to a peer.
  rpc Bootstrap(BootstrapRequest) returns (BootstrapResponse);

  // Identity returns the local identity info.
  rpc Identity(IdentityRequest) returns (IdentityResponse);
}

message AgentStatusRequest {}

message AgentStatusResponse {
  bool ready = 1;
  string peer_id = 2;
  int32 connected_peers = 3;
  int32 active_handshakes = 4;
  string state = 5;
}

message PeersRequest {}

message PeersResponse {
  repeated PeerInfo peers = 1;
}

message PeerInfo {
  string peer_id = 1;
  repeated string addrs = 2;
  string connection_state = 3;
}

message BootstrapRequest {
  string multiaddr = 1;
}

message BootstrapResponse {
  bool success = 1;
  string error = 2;
  string peer_id = 3;
}

message IdentityRequest {}

message IdentityResponse {
  string peer_id = 1;
  string did = 2;
  repeated string listen_addrs = 3;
}
```

**Step 2: Regenerate Go code**

Run: `cd api/proto && go generate`

**Step 3: Verify compilation**

Run: `go build ./api/proto/...`
Expected: SUCCESS

**Step 4: Commit**

```bash
git add api/proto/
git commit -m "[Feat][Proto] Add AgentService for CLI-agent IPC"
```

---

## Task 9: Ingest Daemon - Main Implementation

**Files:**
- Modify: `cmd/mymonad-ingest/main.go`
- Create: `cmd/mymonad-ingest/daemon.go`
- Create: `cmd/mymonad-ingest/daemon_test.go`

**Step 1: Write the failing test**

```go
// cmd/mymonad-ingest/daemon_test.go
package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDaemon_StartStop(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "ingest.sock")
	monadPath := filepath.Join(tmpDir, "monad.bin")
	watchDir := filepath.Join(tmpDir, "watch")
	os.MkdirAll(watchDir, 0755)

	cfg := DaemonConfig{
		SocketPath:     sockPath,
		MonadPath:      monadPath,
		WatchDirs:      []string{watchDir},
		Extensions:     []string{".txt"},
		OllamaURL:      "http://localhost:11434",
		OllamaModel:    "nomic-embed-text",
		OllamaTimeout:  30,
		Dimensions:     768,
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- d.Run(ctx)
	}()

	// Give it time to start
	time.Sleep(100 * time.Millisecond)

	// Verify socket exists
	if _, err := os.Stat(sockPath); os.IsNotExist(err) {
		t.Error("socket file should exist")
	}

	// Stop daemon
	cancel()

	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("daemon did not stop in time")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v ./cmd/mymonad-ingest/... -run TestDaemon`
Expected: FAIL - DaemonConfig undefined

**Step 3: Write implementation**

```go
// cmd/mymonad-ingest/daemon.go
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/mymonad/mymonad/internal/config"
	"github.com/mymonad/mymonad/internal/embed"
	"github.com/mymonad/mymonad/internal/ingest"
	"github.com/mymonad/mymonad/internal/ipc"
	"github.com/mymonad/mymonad/pkg/monad"
)

// DaemonConfig holds ingest daemon configuration.
type DaemonConfig struct {
	SocketPath    string
	MonadPath     string
	WatchDirs     []string
	Extensions    []string
	IgnoreHidden  bool
	OllamaURL     string
	OllamaModel   string
	OllamaTimeout int
	Dimensions    int
}

// Daemon is the ingest service.
type Daemon struct {
	cfg       DaemonConfig
	monad     *monad.Monad
	watcher   *ingest.Watcher
	processor *embed.Processor
	server    *ipc.Server
	logger    *slog.Logger

	mu    sync.RWMutex
	state string
	docs  int64
}

// NewDaemon creates a new ingest daemon.
func NewDaemon(cfg DaemonConfig) (*Daemon, error) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Load or create monad
	m, err := loadOrCreateMonad(cfg.MonadPath, cfg.Dimensions)
	if err != nil {
		return nil, err
	}

	// Create Ollama client and processor
	client := embed.NewOllamaClient(cfg.OllamaURL, cfg.OllamaModel, cfg.OllamaTimeout)
	processor := embed.NewProcessor(client, 512)

	d := &Daemon{
		cfg:       cfg,
		monad:     m,
		processor: processor,
		logger:    logger,
		state:     "idle",
	}

	// Create IPC server
	server, err := ipc.NewServer(cfg.SocketPath, d)
	if err != nil {
		return nil, err
	}
	d.server = server

	return d, nil
}

func loadOrCreateMonad(path string, dims int) (*monad.Monad, error) {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}

	// Try to load existing monad
	m, err := monad.LoadFromFile(path)
	if err == nil {
		return m, nil
	}

	// Create new monad
	return monad.New(dims), nil
}

// Run starts the daemon and blocks until context is canceled.
func (d *Daemon) Run(ctx context.Context) error {
	d.logger.Info("starting ingest daemon",
		"socket", d.cfg.SocketPath,
		"watch_dirs", d.cfg.WatchDirs)

	// Start file watcher
	watcher, err := ingest.NewWatcher()
	if err != nil {
		return err
	}
	d.watcher = watcher

	for _, dir := range d.cfg.WatchDirs {
		if err := watcher.Add(dir); err != nil {
			d.logger.Warn("failed to watch directory", "dir", dir, "error", err)
		}
	}

	// Start IPC server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- d.server.Start()
	}()

	// Process file events
	go d.processEvents(ctx)

	// Wait for shutdown
	select {
	case <-ctx.Done():
		d.logger.Info("shutting down")
	case err := <-serverErr:
		d.logger.Error("server error", "error", err)
		return err
	}

	// Cleanup
	d.watcher.Close()
	d.server.Stop()

	// Save monad
	if err := monad.SaveToFile(d.monad, d.cfg.MonadPath); err != nil {
		d.logger.Error("failed to save monad", "error", err)
	}

	return ctx.Err()
}

func (d *Daemon) processEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-d.watcher.Events():
			if !ok {
				return
			}
			d.handleFileEvent(ctx, event)
		case err, ok := <-d.watcher.Errors():
			if !ok {
				return
			}
			d.logger.Error("watcher error", "error", err)
		}
	}
}

func (d *Daemon) handleFileEvent(ctx context.Context, event ingest.Event) {
	// Check extension
	ext := filepath.Ext(event.Path)
	supported := false
	for _, e := range d.cfg.Extensions {
		if ext == e {
			supported = true
			break
		}
	}
	if !supported {
		return
	}

	// Check hidden files
	if d.cfg.IgnoreHidden && filepath.Base(event.Path)[0] == '.' {
		return
	}

	d.mu.Lock()
	d.state = "embedding"
	d.mu.Unlock()

	defer func() {
		d.mu.Lock()
		d.state = "idle"
		d.mu.Unlock()
	}()

	d.logger.Info("processing file", "path", event.Path)

	embedding, err := d.processor.ProcessFile(ctx, event.Path)
	if err != nil {
		d.logger.Error("failed to process file", "path", event.Path, "error", err)
		return
	}

	if err := d.monad.Update(embedding); err != nil {
		d.logger.Error("failed to update monad", "error", err)
		return
	}

	d.mu.Lock()
	d.docs++
	d.mu.Unlock()

	d.logger.Info("updated monad", "path", event.Path, "version", d.monad.Version)
}

// GetMonad implements ipc.MonadProvider.
func (d *Daemon) GetMonad() ([]byte, int64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// For now, return serialized monad (encryption will be added later)
	data, err := d.monad.MarshalBinary()
	if err != nil {
		return nil, 0, err
	}

	return data, d.monad.Version, nil
}

// GetStatus implements ipc.MonadProvider.
func (d *Daemon) GetStatus() (bool, int64, string) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return true, d.docs, d.state
}
```

**Step 4: Update main.go**

```go
// cmd/mymonad-ingest/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/mymonad/mymonad/internal/config"
)

func main() {
	var (
		configPath = flag.String("config", "", "path to config file")
		watchDirs  = flag.String("watch-dirs", "", "directories to watch (comma-separated)")
		ollamaURL  = flag.String("ollama-url", "", "Ollama API URL")
		model      = flag.String("model", "", "embedding model name")
		logLevel   = flag.String("log-level", "info", "log level (debug, info, warn, error)")
	)
	flag.Parse()

	// Setup logging
	var level slog.Level
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	// Load config
	paths := config.DefaultPaths()
	if err := paths.EnsureDirectories(); err != nil {
		slog.Error("failed to create directories", "error", err)
		os.Exit(1)
	}

	var cfg config.IngestConfig
	var err error

	if *configPath != "" {
		cfg, err = config.LoadIngestConfig(*configPath)
	} else {
		defaultConfigPath := paths.ConfigDir + "/ingest.toml"
		cfg, err = config.LoadIngestConfig(defaultConfigPath)
		if os.IsNotExist(err) {
			cfg = config.DefaultIngestConfig()
			err = nil
		}
	}
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Override with flags
	if *ollamaURL != "" {
		cfg.Ollama.URL = *ollamaURL
	}
	if *model != "" {
		cfg.Ollama.Model = *model
	}

	// Build daemon config
	daemonCfg := DaemonConfig{
		SocketPath:    paths.IngestSocket,
		MonadPath:     cfg.Storage.MonadPath,
		WatchDirs:     cfg.Watch.Directories,
		Extensions:    cfg.Watch.Extensions,
		IgnoreHidden:  cfg.Watch.IgnoreHidden,
		OllamaURL:     cfg.Ollama.URL,
		OllamaModel:   cfg.Ollama.Model,
		OllamaTimeout: cfg.Ollama.TimeoutSeconds,
		Dimensions:    768, // nomic-embed-text dimensions
	}

	daemon, err := NewDaemon(daemonCfg)
	if err != nil {
		slog.Error("failed to create daemon", "error", err)
		os.Exit(1)
	}

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		slog.Info("received shutdown signal")
		cancel()
	}()

	// Run daemon
	if err := daemon.Run(ctx); err != nil && err != context.Canceled {
		slog.Error("daemon error", "error", err)
		os.Exit(1)
	}

	fmt.Println("mymonad-ingest stopped")
}
```

**Step 5: Run test**

Run: `go test -v ./cmd/mymonad-ingest/... -run TestDaemon`
Expected: May fail due to missing Monad methods - implement those first

**Step 6: Add missing Monad methods if needed, then commit**

```bash
git add cmd/mymonad-ingest/
git commit -m "[Feat][Ingest] Implement ingest daemon with file watching and Ollama"
```

---

## Task 10: Add Monad Binary Serialization

**Files:**
- Modify: `pkg/monad/monad.go`
- Modify: `pkg/monad/monad_test.go`

**Step 1: Write the failing test**

```go
// Add to pkg/monad/monad_test.go

func TestMonad_MarshalUnmarshal(t *testing.T) {
	m := New(384)
	m.Update(make([]float32, 384))
	m.Update(make([]float32, 384))

	data, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	m2 := &Monad{}
	if err := m2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if m2.Version != m.Version {
		t.Errorf("version mismatch: %d != %d", m2.Version, m.Version)
	}
	if m2.DocCount != m.DocCount {
		t.Errorf("doc count mismatch: %d != %d", m2.DocCount, m.DocCount)
	}
	if len(m2.Vector) != len(m.Vector) {
		t.Errorf("vector length mismatch")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v ./pkg/monad/... -run TestMonad_Marshal`
Expected: FAIL - MarshalBinary undefined

**Step 3: Write implementation**

```go
// Add to pkg/monad/monad.go

import (
	"encoding/binary"
	"io"
)

// MarshalBinary encodes the Monad to binary format.
func (m *Monad) MarshalBinary() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Format: version(8) + doccount(8) + updatedat(8) + dims(4) + vector(dims*4)
	size := 8 + 8 + 8 + 4 + len(m.Vector)*4
	buf := make([]byte, size)

	offset := 0
	binary.LittleEndian.PutUint64(buf[offset:], uint64(m.Version))
	offset += 8
	binary.LittleEndian.PutUint64(buf[offset:], uint64(m.DocCount))
	offset += 8
	binary.LittleEndian.PutUint64(buf[offset:], uint64(m.UpdatedAt.UnixNano()))
	offset += 8
	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(m.Vector)))
	offset += 4

	for _, v := range m.Vector {
		binary.LittleEndian.PutUint32(buf[offset:], math.Float32bits(v))
		offset += 4
	}

	return buf, nil
}

// UnmarshalBinary decodes the Monad from binary format.
func (m *Monad) UnmarshalBinary(data []byte) error {
	if len(data) < 28 { // minimum header size
		return errors.New("monad: data too short")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	offset := 0
	m.Version = int64(binary.LittleEndian.Uint64(data[offset:]))
	offset += 8
	m.DocCount = int64(binary.LittleEndian.Uint64(data[offset:]))
	offset += 8
	m.UpdatedAt = time.Unix(0, int64(binary.LittleEndian.Uint64(data[offset:])))
	offset += 8
	dims := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4

	if len(data) < offset+dims*4 {
		return errors.New("monad: data too short for vector")
	}

	m.Vector = make([]float32, dims)
	for i := 0; i < dims; i++ {
		m.Vector[i] = math.Float32frombits(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
	}

	return nil
}

// LoadFromFile loads a Monad from a file.
func LoadFromFile(path string) (*Monad, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	m := &Monad{}
	if err := m.UnmarshalBinary(data); err != nil {
		return nil, err
	}

	return m, nil
}

// SaveToFile saves a Monad to a file atomically.
func SaveToFile(m *Monad, path string) error {
	data, err := m.MarshalBinary()
	if err != nil {
		return err
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
}
```

**Step 4: Add imports and run test**

Run: `go test -v ./pkg/monad/... -run TestMonad_Marshal`
Expected: PASS

**Step 5: Commit**

```bash
git add pkg/monad/
git commit -m "[Feat][Monad] Add binary serialization and file persistence"
```

---

## Task 11: Agent Daemon Implementation

**Files:**
- Modify: `cmd/mymonad-agent/main.go`
- Create: `cmd/mymonad-agent/daemon.go`
- Create: `cmd/mymonad-agent/daemon_test.go`

(Similar structure to ingest daemon - implements P2P host, discovery, IPC server)

---

## Task 12: CLI Implementation

**Files:**
- Modify: `cmd/mymonad-cli/main.go`
- Create: `cmd/mymonad-cli/commands.go`

(Implements status, peers, bootstrap, identity commands)

---

## Task 13: Integration Tests

**Files:**
- Create: `tests/integration_test.go`

(Tests full pipeline: start ingest → create file → verify monad updates)

---

## Task 14: Update README

**Files:**
- Modify: `README.md`

(Update with actual usage examples, configuration, and troubleshooting)

---

## Execution Checklist

After each task:
1. Run `go test -race ./...` - all tests pass
2. Run `go build ./...` - compiles cleanly
3. Check coverage hasn't dropped below 80%
4. Commit with descriptive message

Final verification:
1. Start `mymonad-ingest` with Ollama running
2. Create a test file in watched directory
3. Verify monad updates via `mymonad-cli status`
4. Start `mymonad-agent`
5. Verify peer discovery works

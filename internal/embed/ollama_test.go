// internal/embed/ollama_test.go
package embed

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// ollamaRequest represents the expected request body to Ollama API.
type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

// ollamaResponse represents the response from Ollama API.
type ollamaResponse struct {
	Embedding []float32 `json:"embedding"`
}

func TestOllamaClient_Embed(t *testing.T) {
	// Expected embedding (768 dimensions for nomic-embed-text, using 5 for simplicity)
	expectedEmbedding := []float32{0.1, 0.2, 0.3, 0.4, 0.5}

	// Track request details for verification
	var receivedRequest ollamaRequest
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)

		// Verify HTTP method
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}

		// Verify endpoint
		if r.URL.Path != "/api/embeddings" {
			t.Errorf("Expected /api/embeddings path, got %s", r.URL.Path)
		}

		// Verify content type
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", ct)
		}

		// Decode request body
		if err := json.NewDecoder(r.Body).Decode(&receivedRequest); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		// Return embedding response
		resp := ollamaResponse{Embedding: expectedEmbedding}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	// Create client
	client := NewOllamaClient(server.URL, "nomic-embed-text", 30)

	// Call Embed
	ctx := context.Background()
	embedding, err := client.Embed(ctx, "test document text")
	if err != nil {
		t.Fatalf("Embed failed: %v", err)
	}

	// Verify request was made correctly
	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("Expected 1 request, got %d", requestCount)
	}

	if receivedRequest.Model != "nomic-embed-text" {
		t.Errorf("Expected model 'nomic-embed-text', got '%s'", receivedRequest.Model)
	}

	if receivedRequest.Prompt != "test document text" {
		t.Errorf("Expected prompt 'test document text', got '%s'", receivedRequest.Prompt)
	}

	// Verify response
	if len(embedding) != len(expectedEmbedding) {
		t.Fatalf("Expected embedding length %d, got %d", len(expectedEmbedding), len(embedding))
	}

	for i, v := range expectedEmbedding {
		if embedding[i] != v {
			t.Errorf("Embedding[%d] mismatch: expected %f, got %f", i, v, embedding[i])
		}
	}
}

func TestOllamaClient_EmbedRetry(t *testing.T) {
	var requestCount int32
	expectedEmbedding := []float32{0.5, 0.6, 0.7}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)

		// First two requests fail with 503, third succeeds
		if count < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		// Third request succeeds
		resp := ollamaResponse{Embedding: expectedEmbedding}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	// Create client with short timeout for faster tests
	client := NewOllamaClient(server.URL, "nomic-embed-text", 30)

	ctx := context.Background()
	embedding, err := client.Embed(ctx, "retry test")
	if err != nil {
		t.Fatalf("Embed should have succeeded after retries: %v", err)
	}

	// Verify exactly 3 attempts were made
	if atomic.LoadInt32(&requestCount) != 3 {
		t.Errorf("Expected 3 requests (2 failures + 1 success), got %d", requestCount)
	}

	// Verify embedding returned
	if len(embedding) != len(expectedEmbedding) {
		t.Fatalf("Expected embedding length %d, got %d", len(expectedEmbedding), len(embedding))
	}
}

func TestOllamaClient_EmbedRetryExhausted(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		// Always return 503
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewOllamaClient(server.URL, "nomic-embed-text", 30)

	ctx := context.Background()
	_, err := client.Embed(ctx, "always fails")
	if err == nil {
		t.Fatal("Expected error after all retries exhausted")
	}

	// Should be ErrOllamaUnavailable
	if err != ErrOllamaUnavailable {
		t.Errorf("Expected ErrOllamaUnavailable, got: %v", err)
	}

	// Verify exactly 3 attempts were made
	if atomic.LoadInt32(&requestCount) != 3 {
		t.Errorf("Expected 3 requests (all retries), got %d", requestCount)
	}
}

func TestOllamaClient_EmbedTimeout(t *testing.T) {
	// Use a channel to signal when to unblock the handler
	done := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wait until request context is done OR test signals completion
		select {
		case <-r.Context().Done():
			return
		case <-done:
			return
		}
	}))
	// Custom cleanup: close client connections before server
	defer func() {
		close(done)
		server.CloseClientConnections()
		server.Close()
	}()

	// Create client with very short timeout (1 second)
	client := NewOllamaClient(server.URL, "nomic-embed-text", 1)

	ctx := context.Background()
	start := time.Now()
	_, err := client.Embed(ctx, "timeout test")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Expected timeout error, got nil")
	}

	// Client timeout should prevent retries (non-503 error path)
	// Should complete around 1s (single timeout, no retry on timeout errors)
	if elapsed > 5*time.Second {
		t.Errorf("Expected timeout within ~1s, took %v", elapsed)
	}
}

func TestOllamaClient_EmbedContextCancellation(t *testing.T) {
	// Use a channel to signal when to unblock the handler
	done := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wait until request context is done OR test signals completion
		select {
		case <-r.Context().Done():
			return
		case <-done:
			return
		}
	}))
	// Custom cleanup: close client connections before server
	defer func() {
		close(done)
		server.CloseClientConnections()
		server.Close()
	}()

	client := NewOllamaClient(server.URL, "nomic-embed-text", 30)

	// Create a context that we'll cancel quickly
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := client.Embed(ctx, "cancel test")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Expected context cancellation error, got nil")
	}

	// Should complete quickly after cancellation
	if elapsed > 2*time.Second {
		t.Errorf("Expected quick cancellation, took %v", elapsed)
	}
}

func TestOllamaClient_EmbedNon503Error(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		// Return 400 Bad Request - should NOT retry
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "invalid model"}`))
	}))
	defer server.Close()

	client := NewOllamaClient(server.URL, "invalid-model", 30)

	ctx := context.Background()
	_, err := client.Embed(ctx, "test")
	if err == nil {
		t.Fatal("Expected error for 400 response")
	}

	// Should NOT retry on 400 - only 1 request
	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("Expected 1 request (no retry on 400), got %d", requestCount)
	}
}

func TestOllamaClient_EmbedEmptyText(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Even empty text should work - Ollama will return an embedding
		resp := ollamaResponse{Embedding: []float32{0.0, 0.0, 0.0}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOllamaClient(server.URL, "nomic-embed-text", 30)

	ctx := context.Background()
	embedding, err := client.Embed(ctx, "")
	if err != nil {
		t.Fatalf("Embed failed for empty text: %v", err)
	}

	if len(embedding) != 3 {
		t.Errorf("Expected 3-dimensional embedding, got %d", len(embedding))
	}
}

func TestNewOllamaClient(t *testing.T) {
	client := NewOllamaClient("http://localhost:11434", "nomic-embed-text", 30)

	if client == nil {
		t.Fatal("NewOllamaClient returned nil")
	}

	// Verify internal fields are set correctly
	if client.baseURL != "http://localhost:11434" {
		t.Errorf("Expected baseURL 'http://localhost:11434', got '%s'", client.baseURL)
	}

	if client.model != "nomic-embed-text" {
		t.Errorf("Expected model 'nomic-embed-text', got '%s'", client.model)
	}

	if client.client == nil {
		t.Error("HTTP client should not be nil")
	}
}

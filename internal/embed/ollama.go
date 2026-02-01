// internal/embed/ollama.go
package embed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ErrOllamaUnavailable is returned when Ollama returns 503 Service Unavailable
// after all retries are exhausted.
var ErrOllamaUnavailable = errors.New("ollama: service unavailable")

// OllamaClient communicates with Ollama for generating embeddings.
type OllamaClient struct {
	baseURL string
	model   string
	client  *http.Client
}

// ollamaEmbedRequest is the request body for Ollama embeddings API.
type ollamaEmbedRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

// ollamaEmbedResponse is the response from Ollama embeddings API.
type ollamaEmbedResponse struct {
	Embedding []float32 `json:"embedding"`
}

// NewOllamaClient creates a new Ollama client with the specified base URL,
// model name, and timeout in seconds.
func NewOllamaClient(baseURL, model string, timeoutSeconds int) *OllamaClient {
	return &OllamaClient{
		baseURL: baseURL,
		model:   model,
		client: &http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		},
	}
}

// Embed generates an embedding vector for the given text.
// It retries up to 3 times with exponential backoff (1s, 2s, 4s) on transient errors.
// HTTP 503 (Service Unavailable) is treated as retryable.
func (c *OllamaClient) Embed(ctx context.Context, text string) ([]float32, error) {
	const maxRetries = 3
	backoffDurations := []time.Duration{
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
	}

	var lastErr error
	var last503 bool

	for attempt := 0; attempt < maxRetries; attempt++ {
		// Check context before attempt
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		// Wait for backoff (except on first attempt)
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoffDurations[attempt-1]):
			}
		}

		embedding, err, is503 := c.doEmbed(ctx, text)
		if err == nil {
			return embedding, nil
		}

		lastErr = err
		last503 = is503

		// Only retry on 503 errors
		if !is503 {
			return nil, lastErr
		}
	}

	// All retries exhausted
	if last503 {
		return nil, ErrOllamaUnavailable
	}
	return nil, lastErr
}

// doEmbed performs a single embedding request.
// Returns (embedding, error, is503).
func (c *OllamaClient) doEmbed(ctx context.Context, text string) ([]float32, error, bool) {
	// Build request body
	reqBody := ollamaEmbedRequest{
		Model:  c.model,
		Prompt: text,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err), false
	}

	// Create HTTP request
	url := c.baseURL + "/api/embeddings"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err), false
	}

	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := c.client.Do(req)
	if err != nil {
		// Network errors, timeouts, context cancellation
		return nil, fmt.Errorf("request failed: %w", err), false
	}
	defer resp.Body.Close()

	// Handle 503 Service Unavailable as retryable
	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, ErrOllamaUnavailable, true
	}

	// Handle other non-2xx responses
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama API error: status %d: %s", resp.StatusCode, string(body)), false
	}

	// Decode response
	var embedResp ollamaEmbedResponse
	if err := json.NewDecoder(resp.Body).Decode(&embedResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err), false
	}

	return embedResp.Embedding, nil, false
}

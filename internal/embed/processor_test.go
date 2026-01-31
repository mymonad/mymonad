// internal/embed/processor_test.go
package embed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// mockEmbedder implements Embedder for testing.
type mockEmbedder struct {
	embedFunc func(ctx context.Context, text string) ([]float32, error)
}

func (m *mockEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	if m.embedFunc != nil {
		return m.embedFunc(ctx, text)
	}
	return make([]float32, 768), nil
}

func TestNewProcessor(t *testing.T) {
	embedder := &mockEmbedder{}
	p := NewProcessor(embedder, 512)

	if p == nil {
		t.Fatal("NewProcessor returned nil")
	}
	if p.embedder != embedder {
		t.Error("Processor has wrong embedder")
	}
	if p.maxTokens != 512 {
		t.Errorf("Expected maxTokens 512, got %d", p.maxTokens)
	}
}

func TestProcessFile_UnsupportedFormat(t *testing.T) {
	embedder := &mockEmbedder{}
	p := NewProcessor(embedder, 512)

	// Create a temp file with unsupported extension
	tmpDir := t.TempDir()
	unsupportedFile := filepath.Join(tmpDir, "test.pdf")
	if err := os.WriteFile(unsupportedFile, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := p.ProcessFile(context.Background(), unsupportedFile)
	if !errors.Is(err, ErrUnsupportedFormat) {
		t.Errorf("Expected ErrUnsupportedFormat, got %v", err)
	}
}

func TestProcessFile_EmptyFile(t *testing.T) {
	embedder := &mockEmbedder{}
	p := NewProcessor(embedder, 512)

	// Create empty .txt file
	tmpDir := t.TempDir()
	emptyFile := filepath.Join(tmpDir, "empty.txt")
	if err := os.WriteFile(emptyFile, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := p.ProcessFile(context.Background(), emptyFile)
	if !errors.Is(err, ErrEmptyFile) {
		t.Errorf("Expected ErrEmptyFile, got %v", err)
	}
}

func TestProcessFile_WhitespaceOnlyFile(t *testing.T) {
	embedder := &mockEmbedder{}
	p := NewProcessor(embedder, 512)

	// Create file with only whitespace
	tmpDir := t.TempDir()
	wsFile := filepath.Join(tmpDir, "whitespace.txt")
	if err := os.WriteFile(wsFile, []byte("   \n\t  \n  "), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := p.ProcessFile(context.Background(), wsFile)
	if !errors.Is(err, ErrEmptyFile) {
		t.Errorf("Expected ErrEmptyFile for whitespace-only file, got %v", err)
	}
}

func TestProcessFile_NonExistentFile(t *testing.T) {
	embedder := &mockEmbedder{}
	p := NewProcessor(embedder, 512)

	_, err := p.ProcessFile(context.Background(), "/nonexistent/file.txt")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestProcessFile_TxtFile(t *testing.T) {
	callCount := 0
	embedder := &mockEmbedder{
		embedFunc: func(ctx context.Context, text string) ([]float32, error) {
			callCount++
			// Return simple embedding
			return []float32{1.0, 2.0, 3.0}, nil
		},
	}
	p := NewProcessor(embedder, 512)

	// Create a .txt file
	tmpDir := t.TempDir()
	txtFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(txtFile, []byte("Hello world!"), 0644); err != nil {
		t.Fatal(err)
	}

	embedding, err := p.ProcessFile(context.Background(), txtFile)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if callCount != 1 {
		t.Errorf("Expected 1 embed call, got %d", callCount)
	}

	if len(embedding) != 3 {
		t.Errorf("Expected embedding length 3, got %d", len(embedding))
	}

	// Single chunk, so embedding should be returned directly
	expected := []float32{1.0, 2.0, 3.0}
	for i, v := range embedding {
		if v != expected[i] {
			t.Errorf("Embedding[%d] = %f, want %f", i, v, expected[i])
		}
	}
}

func TestProcessFile_MdFile(t *testing.T) {
	embedder := &mockEmbedder{
		embedFunc: func(ctx context.Context, text string) ([]float32, error) {
			return []float32{1.0, 1.0}, nil
		},
	}
	p := NewProcessor(embedder, 512)

	// Create a .md file
	tmpDir := t.TempDir()
	mdFile := filepath.Join(tmpDir, "test.md")
	if err := os.WriteFile(mdFile, []byte("# Markdown content"), 0644); err != nil {
		t.Fatal(err)
	}

	embedding, err := p.ProcessFile(context.Background(), mdFile)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(embedding) != 2 {
		t.Errorf("Expected embedding length 2, got %d", len(embedding))
	}
}

func TestProcessFile_MultipleChunks_AveragesEmbeddings(t *testing.T) {
	chunkCount := 0
	embedder := &mockEmbedder{
		embedFunc: func(ctx context.Context, text string) ([]float32, error) {
			chunkCount++
			// Return embedding where each element equals the chunk number
			// This makes it easy to verify averaging
			n := float32(chunkCount)
			return []float32{n, n * 2, n * 3}, nil
		},
	}
	// Use small maxTokens to force chunking
	p := NewProcessor(embedder, 5)

	// Create content that will be chunked (at 5 tokens ~ 20 chars per chunk)
	tmpDir := t.TempDir()
	txtFile := filepath.Join(tmpDir, "chunked.txt")
	content := "First paragraph here with some words.\n\nSecond paragraph here with more words."
	if err := os.WriteFile(txtFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	embedding, err := p.ProcessFile(context.Background(), txtFile)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if chunkCount < 2 {
		t.Fatalf("Expected at least 2 chunks, got %d", chunkCount)
	}

	// Calculate expected average dynamically
	// For N chunks with embeddings [1,2,3], [2,4,6], ..., [N,2N,3N]
	// Sum of first dimension: 1+2+...+N = N(N+1)/2
	// Average of first dimension: (N+1)/2
	n := float32(chunkCount)
	expectedAvg := (n + 1) / 2 // Average of 1 to N
	expected := []float32{expectedAvg, expectedAvg * 2, expectedAvg * 3}

	if len(embedding) != len(expected) {
		t.Fatalf("Expected embedding length %d, got %d", len(expected), len(embedding))
	}

	for i, v := range embedding {
		if v != expected[i] {
			t.Errorf("Embedding[%d] = %f, want %f", i, v, expected[i])
		}
	}
}

func TestProcessFile_EmbedderError(t *testing.T) {
	expectedErr := errors.New("embedding failed")
	embedder := &mockEmbedder{
		embedFunc: func(ctx context.Context, text string) ([]float32, error) {
			return nil, expectedErr
		},
	}
	p := NewProcessor(embedder, 512)

	tmpDir := t.TempDir()
	txtFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(txtFile, []byte("Hello world!"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := p.ProcessFile(context.Background(), txtFile)
	if err == nil {
		t.Error("Expected error from embedder")
	}
}

func TestProcessFile_ContextCancellation(t *testing.T) {
	embedder := &mockEmbedder{
		embedFunc: func(ctx context.Context, text string) ([]float32, error) {
			return nil, ctx.Err()
		},
	}
	p := NewProcessor(embedder, 512)

	tmpDir := t.TempDir()
	txtFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(txtFile, []byte("Hello world!"), 0644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := p.ProcessFile(ctx, txtFile)
	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestSupportedExtensions(t *testing.T) {
	// Verify supported extensions
	if !SupportedExtensions[".txt"] {
		t.Error(".txt should be supported")
	}
	if !SupportedExtensions[".md"] {
		t.Error(".md should be supported")
	}
	if SupportedExtensions[".pdf"] {
		t.Error(".pdf should not be supported")
	}
	if SupportedExtensions[".doc"] {
		t.Error(".doc should not be supported")
	}
}

func TestAverageEmbeddings(t *testing.T) {
	tests := []struct {
		name       string
		embeddings [][]float32
		expected   []float32
	}{
		{
			name:       "single embedding",
			embeddings: [][]float32{{1.0, 2.0, 3.0}},
			expected:   []float32{1.0, 2.0, 3.0},
		},
		{
			name: "two embeddings",
			embeddings: [][]float32{
				{2.0, 4.0, 6.0},
				{4.0, 8.0, 12.0},
			},
			expected: []float32{3.0, 6.0, 9.0},
		},
		{
			name: "three embeddings",
			embeddings: [][]float32{
				{1.0, 2.0, 3.0},
				{2.0, 4.0, 6.0},
				{3.0, 6.0, 9.0},
			},
			expected: []float32{2.0, 4.0, 6.0},
		},
		{
			name:       "empty slice",
			embeddings: [][]float32{},
			expected:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := averageEmbeddings(tt.embeddings)

			if tt.expected == nil {
				if result != nil {
					t.Errorf("Expected nil, got %v", result)
				}
				return
			}

			if len(result) != len(tt.expected) {
				t.Fatalf("Length mismatch: got %d, want %d", len(result), len(tt.expected))
			}

			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("Result[%d] = %f, want %f", i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestProcessFile_CaseSensitiveExtensions(t *testing.T) {
	embedder := &mockEmbedder{
		embedFunc: func(ctx context.Context, text string) ([]float32, error) {
			return []float32{1.0}, nil
		},
	}
	p := NewProcessor(embedder, 512)

	tmpDir := t.TempDir()

	// Test uppercase .TXT
	txtFile := filepath.Join(tmpDir, "test.TXT")
	if err := os.WriteFile(txtFile, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	// Should work with case-insensitive extension matching
	embedding, err := p.ProcessFile(context.Background(), txtFile)
	if err != nil {
		t.Fatalf("Expected .TXT to be supported (case-insensitive), got error: %v", err)
	}
	if len(embedding) != 1 {
		t.Errorf("Expected embedding length 1, got %d", len(embedding))
	}
}

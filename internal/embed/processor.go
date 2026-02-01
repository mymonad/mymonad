// internal/embed/processor.go
package embed

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Errors for the processor.
var (
	ErrUnsupportedFormat  = errors.New("embed: unsupported file format")
	ErrEmptyFile          = errors.New("embed: file is empty")
	ErrDimensionMismatch  = errors.New("embed: embedding dimension mismatch")
)

// SupportedExtensions lists processable file types.
var SupportedExtensions = map[string]bool{".txt": true, ".md": true}

// Embedder generates embeddings from text.
// OllamaClient implements this interface.
type Embedder interface {
	Embed(ctx context.Context, text string) ([]float32, error)
}

// Processor handles file reading, chunking, and embedding.
type Processor struct {
	embedder  Embedder
	maxTokens int
}

// NewProcessor creates a new Processor with the given embedder and max tokens per chunk.
func NewProcessor(embedder Embedder, maxTokens int) *Processor {
	return &Processor{
		embedder:  embedder,
		maxTokens: maxTokens,
	}
}

// ProcessFile reads a file, chunks its content, embeds each chunk,
// and returns the average of all chunk embeddings as a single vector.
// Returns ErrUnsupportedFormat for unsupported file extensions.
// Returns ErrEmptyFile for empty or whitespace-only files.
func (p *Processor) ProcessFile(ctx context.Context, path string) ([]float32, error) {
	// Check file extension (case-insensitive)
	ext := strings.ToLower(filepath.Ext(path))
	if !SupportedExtensions[ext] {
		return nil, ErrUnsupportedFormat
	}

	// Read file content
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Check for empty content
	text := strings.TrimSpace(string(content))
	if text == "" {
		return nil, ErrEmptyFile
	}

	// Chunk the text
	chunks := ChunkText(text, p.maxTokens)
	if len(chunks) == 0 {
		return nil, ErrEmptyFile
	}

	// Embed each chunk
	embeddings := make([][]float32, 0, len(chunks))
	for _, chunk := range chunks {
		// Check context before each embedding call
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		embedding, err := p.embedder.Embed(ctx, chunk)
		if err != nil {
			return nil, err
		}
		embeddings = append(embeddings, embedding)
	}

	// Average all embeddings into a single vector
	avg, err := averageEmbeddings(embeddings)
	if err != nil {
		return nil, err
	}
	return avg, nil
}

// averageEmbeddings computes the element-wise average of multiple embeddings.
// Returns nil if the input slice is empty.
// Returns ErrDimensionMismatch if embeddings have inconsistent dimensions.
func averageEmbeddings(embeddings [][]float32) ([]float32, error) {
	if len(embeddings) == 0 {
		return nil, nil
	}

	if len(embeddings) == 1 {
		return embeddings[0], nil
	}

	// Get dimension from first embedding
	dim := len(embeddings[0])
	result := make([]float32, dim)

	// Validate dimensions and sum all embeddings
	for i, emb := range embeddings {
		if len(emb) != dim {
			return nil, fmt.Errorf("%w: embedding %d has %d dimensions, expected %d",
				ErrDimensionMismatch, i, len(emb), dim)
		}
		for j, v := range emb {
			result[j] += v
		}
	}

	// Divide by count to get average
	count := float32(len(embeddings))
	for i := range result {
		result[i] /= count
	}

	return result, nil
}

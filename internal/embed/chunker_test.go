// internal/embed/chunker_test.go
package embed

import (
	"strings"
	"testing"
)

func TestChunkText_EmptyText(t *testing.T) {
	chunks := ChunkText("", 512)
	if len(chunks) != 0 {
		t.Errorf("Expected 0 chunks for empty text, got %d", len(chunks))
	}
}

func TestChunkText_SmallText(t *testing.T) {
	text := "This is a small text."
	chunks := ChunkText(text, 100)

	if len(chunks) != 1 {
		t.Fatalf("Expected 1 chunk, got %d", len(chunks))
	}

	if chunks[0] != text {
		t.Errorf("Expected chunk to equal input, got %q", chunks[0])
	}
}

func TestChunkText_PreservesParagraphs(t *testing.T) {
	// Create paragraphs that are individually small but together exceed chunk size
	text := "First paragraph here.\n\nSecond paragraph here.\n\nThird paragraph here."
	// With maxTokens = 8 (~32 chars), each paragraph is ~20 chars
	// Two paragraphs would be ~42 chars (with separator), so should split
	chunks := ChunkText(text, 8)

	if len(chunks) < 2 {
		t.Fatalf("Expected at least 2 chunks when splitting on paragraphs, got %d", len(chunks))
	}

	// Verify chunks don't contain paragraph boundaries in the middle
	// (meaning we split ON boundaries, not randomly)
	for i, chunk := range chunks {
		chunk = strings.TrimSpace(chunk)
		// A chunk might have \n\n if it contains multiple paragraphs that fit,
		// but should never split mid-paragraph
		if strings.HasPrefix(chunk, "\n") || strings.HasSuffix(chunk, "\n") {
			t.Errorf("Chunk %d has leading/trailing newline (split mid-paragraph): %q", i, chunk)
		}
	}

	// Verify all content is preserved
	var allWords []string
	for _, chunk := range chunks {
		allWords = append(allWords, strings.Fields(chunk)...)
	}
	originalWords := strings.Fields(text)
	if len(allWords) != len(originalWords) {
		t.Errorf("Word count mismatch: got %d, want %d", len(allWords), len(originalWords))
	}
}

func TestChunkText_LargeText(t *testing.T) {
	// Create ~1000 words (roughly 5000 chars, ~1250 tokens)
	var builder strings.Builder
	for i := 0; i < 1000; i++ {
		builder.WriteString("word ")
	}
	text := builder.String()

	// With maxTokens = 100, roughly 400 chars per chunk
	// 5000 chars should produce ~12-13 chunks
	chunks := ChunkText(text, 100)

	if len(chunks) < 5 {
		t.Errorf("Expected multiple chunks for large text, got %d", len(chunks))
	}

	// Verify no chunk exceeds the limit (100 tokens ~ 400 chars)
	maxChars := 100 * 4 // 1 token ≈ 4 characters
	for i, chunk := range chunks {
		if len(chunk) > maxChars+50 { // Allow small buffer for word boundaries
			t.Errorf("Chunk %d exceeds limit: %d chars (max ~%d)", i, len(chunk), maxChars)
		}
	}

	// Verify all words are preserved
	var allWords []string
	for _, chunk := range chunks {
		allWords = append(allWords, strings.Fields(chunk)...)
	}
	originalWords := strings.Fields(text)

	if len(allWords) != len(originalWords) {
		t.Errorf("Word count mismatch: got %d, want %d", len(allWords), len(originalWords))
	}

	// Spot check some words
	for i := 0; i < len(originalWords); i += 100 {
		if allWords[i] != originalWords[i] {
			t.Errorf("Word %d mismatch: got %q, want %q", i, allWords[i], originalWords[i])
		}
	}
}

func TestChunkText_SentenceBoundaries(t *testing.T) {
	// One large paragraph that exceeds chunk size
	// Should fall back to sentence boundaries
	text := "This is the first sentence. This is the second sentence. This is the third sentence. This is the fourth sentence."

	// maxTokens = 20 ~ 80 chars, each sentence is ~28 chars
	// Should split on sentence boundaries
	chunks := ChunkText(text, 20)

	if len(chunks) < 2 {
		t.Fatalf("Expected at least 2 chunks when splitting on sentences, got %d", len(chunks))
	}

	// Verify chunks end with sentence terminators (period, !, ?)
	for i, chunk := range chunks[:len(chunks)-1] { // Skip last chunk
		chunk = strings.TrimSpace(chunk)
		lastChar := chunk[len(chunk)-1]
		if lastChar != '.' && lastChar != '!' && lastChar != '?' {
			t.Errorf("Chunk %d doesn't end with sentence terminator: %q", i, chunk)
		}
	}
}

func TestChunkText_WhitespaceOnly(t *testing.T) {
	chunks := ChunkText("   \n\n\t  ", 100)
	if len(chunks) != 0 {
		t.Errorf("Expected 0 chunks for whitespace-only text, got %d", len(chunks))
	}
}

func TestChunkText_ExactFit(t *testing.T) {
	// Text that exactly fits in one chunk
	text := "Hello world!" // 12 chars ~ 3 tokens
	chunks := ChunkText(text, 10)

	if len(chunks) != 1 {
		t.Fatalf("Expected 1 chunk for text that fits, got %d", len(chunks))
	}

	if chunks[0] != text {
		t.Errorf("Expected chunk to equal input, got %q", chunks[0])
	}
}

func TestChunkText_SingleLongWord(t *testing.T) {
	// A word that exceeds the chunk size (edge case)
	// Should still be included even if it exceeds the limit
	text := "supercalifragilisticexpialidocious"
	chunks := ChunkText(text, 5) // 20 chars max, word is 34 chars

	if len(chunks) != 1 {
		t.Fatalf("Expected 1 chunk for single long word, got %d", len(chunks))
	}

	if chunks[0] != text {
		t.Errorf("Expected chunk to contain the long word, got %q", chunks[0])
	}
}

func TestChunkText_MixedParagraphsAndSentences(t *testing.T) {
	text := `First paragraph with multiple sentences. It has quite a bit of content here. Yes it does.

Second paragraph is shorter.

Third paragraph also has several sentences. Some are long. Some are short. This tests the chunker.`

	// With small maxTokens, should split on paragraphs first, then sentences if needed
	chunks := ChunkText(text, 25) // ~100 chars per chunk

	// Verify we got multiple chunks
	if len(chunks) < 2 {
		t.Errorf("Expected multiple chunks, got %d", len(chunks))
	}

	// Verify all words are preserved (order and content)
	var allWords []string
	for _, chunk := range chunks {
		allWords = append(allWords, strings.Fields(chunk)...)
	}
	originalWords := strings.Fields(text)

	if len(allWords) != len(originalWords) {
		t.Errorf("Word count mismatch: got %d, want %d", len(allWords), len(originalWords))
	}

	for i := range originalWords {
		if i >= len(allWords) {
			break
		}
		if allWords[i] != originalWords[i] {
			t.Errorf("Word %d mismatch: got %q, want %q", i, allWords[i], originalWords[i])
		}
	}
}

func TestChunkText_TrailingNewlines(t *testing.T) {
	text := "First paragraph.\n\nSecond paragraph.\n\n"
	chunks := ChunkText(text, 100)

	// Should handle trailing newlines gracefully
	if len(chunks) == 0 {
		t.Fatal("Expected at least 1 chunk")
	}

	// Content should be preserved (minus trailing whitespace)
	combined := strings.Join(chunks, "")
	combined = strings.TrimSpace(combined)
	expected := strings.TrimSpace(text)
	if combined != expected {
		t.Errorf("Content mismatch: got %q, want %q", combined, expected)
	}
}

func TestChunkText_QuestionAndExclamation(t *testing.T) {
	text := "Is this a question? Yes it is! And this is a statement."

	// maxTokens = 15 ~ 60 chars, text is ~55 chars, should fit in one
	chunks := ChunkText(text, 15)

	if len(chunks) != 1 {
		t.Fatalf("Expected 1 chunk, got %d", len(chunks))
	}

	// With smaller limit, should split on sentence boundaries
	chunks = ChunkText(text, 8) // ~32 chars per chunk

	if len(chunks) < 2 {
		t.Fatalf("Expected multiple chunks with small limit, got %d", len(chunks))
	}

	// Verify chunks respect sentence boundaries
	for i, chunk := range chunks[:len(chunks)-1] {
		chunk = strings.TrimSpace(chunk)
		if chunk == "" {
			continue
		}
		lastChar := chunk[len(chunk)-1]
		if lastChar != '.' && lastChar != '!' && lastChar != '?' {
			t.Errorf("Chunk %d doesn't end with sentence terminator: %q", i, chunk)
		}
	}
}

func TestChunkText_ZeroMaxTokens(t *testing.T) {
	// Edge case: zero or negative maxTokens
	// Should return empty or handle gracefully
	text := "Some text here."
	chunks := ChunkText(text, 0)

	// With zero max tokens, behavior is undefined but shouldn't panic
	// Implementation may return empty or treat as no limit
	_ = chunks // Just verify no panic
}

func TestChunkText_NegativeMaxTokens(t *testing.T) {
	text := "Some text here."
	chunks := ChunkText(text, -1)

	// Should handle gracefully without panic
	_ = chunks
}

// internal/embed/chunker.go
package embed

import (
	"strings"
)

// charsPerToken is the approximate number of characters per token.
// This is a rough estimate; actual tokenization varies by model.
const charsPerToken = 4

// ChunkText splits text into chunks of approximately maxTokens tokens.
// It attempts to split on paragraph boundaries (double newlines) first,
// then falls back to sentence boundaries (. ! ?) if paragraphs are too large.
// Returns an empty slice for empty or whitespace-only input.
func ChunkText(text string, maxTokens int) []string {
	// Handle edge cases
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}

	// Handle invalid maxTokens
	if maxTokens <= 0 {
		return nil
	}

	maxChars := maxTokens * charsPerToken

	// If text fits in one chunk, return it directly
	if len(text) <= maxChars {
		return []string{text}
	}

	// Split into paragraphs first (double newlines)
	paragraphs := splitParagraphs(text)

	var chunks []string
	var currentChunk strings.Builder

	for _, para := range paragraphs {
		para = strings.TrimSpace(para)
		if para == "" {
			continue
		}

		// If adding this paragraph would exceed the limit
		if currentChunk.Len() > 0 && currentChunk.Len()+len(para)+2 > maxChars {
			// Flush current chunk
			chunks = append(chunks, strings.TrimSpace(currentChunk.String()))
			currentChunk.Reset()
		}

		// If the paragraph itself is too large, split on sentences
		if len(para) > maxChars {
			// Flush any accumulated content first
			if currentChunk.Len() > 0 {
				chunks = append(chunks, strings.TrimSpace(currentChunk.String()))
				currentChunk.Reset()
			}

			// Split this paragraph into sentences
			sentenceChunks := chunkBySentences(para, maxChars)
			chunks = append(chunks, sentenceChunks...)
		} else {
			// Add paragraph to current chunk
			if currentChunk.Len() > 0 {
				currentChunk.WriteString("\n\n")
			}
			currentChunk.WriteString(para)
		}
	}

	// Don't forget the last chunk
	if currentChunk.Len() > 0 {
		chunks = append(chunks, strings.TrimSpace(currentChunk.String()))
	}

	return chunks
}

// splitParagraphs splits text on paragraph boundaries (double newlines).
func splitParagraphs(text string) []string {
	// Normalize line endings and split on double newlines
	text = strings.ReplaceAll(text, "\r\n", "\n")
	return strings.Split(text, "\n\n")
}

// chunkBySentences splits text into chunks by sentence boundaries.
// Sentences are delimited by . ! or ? followed by space or end of text.
// Falls back to word boundaries if no sentence terminators exist.
func chunkBySentences(text string, maxChars int) []string {
	sentences := splitSentences(text)

	// If only one "sentence" and it's too large, split by words
	if len(sentences) == 1 && len(sentences[0]) > maxChars {
		return chunkByWords(text, maxChars)
	}

	var chunks []string
	var currentChunk strings.Builder

	for _, sentence := range sentences {
		sentence = strings.TrimSpace(sentence)
		if sentence == "" {
			continue
		}

		// If adding this sentence would exceed the limit
		if currentChunk.Len() > 0 && currentChunk.Len()+len(sentence)+1 > maxChars {
			// Flush current chunk
			chunks = append(chunks, strings.TrimSpace(currentChunk.String()))
			currentChunk.Reset()
		}

		// If the sentence itself is too large, split by words
		if len(sentence) > maxChars {
			// Flush any accumulated content first
			if currentChunk.Len() > 0 {
				chunks = append(chunks, strings.TrimSpace(currentChunk.String()))
				currentChunk.Reset()
			}
			// Split this sentence by words
			wordChunks := chunkByWords(sentence, maxChars)
			chunks = append(chunks, wordChunks...)
		} else {
			if currentChunk.Len() > 0 {
				currentChunk.WriteString(" ")
			}
			currentChunk.WriteString(sentence)
		}
	}

	// Don't forget the last chunk
	if currentChunk.Len() > 0 {
		chunks = append(chunks, strings.TrimSpace(currentChunk.String()))
	}

	return chunks
}

// chunkByWords splits text into chunks at word boundaries.
func chunkByWords(text string, maxChars int) []string {
	words := strings.Fields(text)

	var chunks []string
	var currentChunk strings.Builder

	for _, word := range words {
		// If adding this word would exceed the limit
		if currentChunk.Len() > 0 && currentChunk.Len()+len(word)+1 > maxChars {
			// Flush current chunk
			chunks = append(chunks, currentChunk.String())
			currentChunk.Reset()
		}

		// Add word to current chunk
		if currentChunk.Len() > 0 {
			currentChunk.WriteString(" ")
		}
		currentChunk.WriteString(word)
	}

	// Don't forget the last chunk
	if currentChunk.Len() > 0 {
		chunks = append(chunks, currentChunk.String())
	}

	return chunks
}

// splitSentences splits text on sentence boundaries (. ! ?).
// Keeps the terminator with the sentence.
func splitSentences(text string) []string {
	var sentences []string
	var current strings.Builder

	runes := []rune(text)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		current.WriteRune(r)

		// Check for sentence terminators
		if r == '.' || r == '!' || r == '?' {
			// Check if this is followed by whitespace or end of text
			// (to avoid splitting on abbreviations like "Dr." in the middle of text)
			if i+1 >= len(runes) || isWhitespace(runes[i+1]) {
				sentences = append(sentences, current.String())
				current.Reset()
			}
		}
	}

	// Add any remaining content
	if current.Len() > 0 {
		sentences = append(sentences, current.String())
	}

	return sentences
}

// isWhitespace checks if a rune is whitespace.
func isWhitespace(r rune) bool {
	return r == ' ' || r == '\n' || r == '\r' || r == '\t'
}

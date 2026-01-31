// Package lsh implements Locality Sensitive Hashing using random hyperplanes.
// This file provides Monad signature generation for privacy-preserving peer discovery.
package lsh

import (
	"time"

	"github.com/mymonad/mymonad/pkg/monad"
)

// MonadSignature represents an LSH signature generated from a Monad's affinity vector.
// It enables peer discovery based on similarity without revealing raw vector data.
type MonadSignature struct {
	// Signature is the LSH signature bits.
	Signature Signature

	// Version is the Monad version when this signature was generated.
	// Used for cache invalidation and change detection.
	Version int64

	// Dimensions is the original vector dimensions.
	Dimensions int

	// NumHashes is the number of hash functions used to generate the signature.
	NumHashes int

	// GeneratedAt records when this signature was created.
	GeneratedAt time.Time
}

// Generator creates MonadSignatures from Monad affinity vectors.
// Thread-safe for concurrent use.
type Generator struct {
	lsh       *LSH
	numHashes int
}

// NewGenerator creates a new signature generator with the specified parameters.
// The seed ensures deterministic hyperplane generation across all nodes using
// the same seed, enabling distributed similarity search.
//
// Parameters:
//   - numHashes: number of hash functions (bits in signature). More bits = higher accuracy.
//   - dimensions: expected vector dimensions. Must match Monad vector dimensions.
//   - seed: random seed for deterministic hyperplane generation.
func NewGenerator(numHashes, dimensions int, seed int64) *Generator {
	return &Generator{
		lsh:       New(numHashes, dimensions, seed),
		numHashes: numHashes,
	}
}

// Generate creates a MonadSignature from the given Monad.
// Returns nil if the Monad is nil or has mismatched dimensions.
//
// The generated signature captures the Monad's position in the vector space
// while preserving similarity relationships - similar vectors produce
// similar signatures with low Hamming distance.
//
// Thread-safe: Creates an atomic snapshot of the Monad for processing.
func (g *Generator) Generate(m *monad.Monad) *MonadSignature {
	if m == nil {
		return nil
	}

	// Clone creates an atomic snapshot of the Monad
	snapshot := m.Clone()

	// Check dimension match
	if len(snapshot.Vector) != g.lsh.Dimensions() {
		return nil
	}

	// Compute LSH signature from vector
	sig := g.lsh.Hash(snapshot.Vector)

	// Handle empty signature (indicates hash failure)
	if sig.Size == 0 {
		return nil
	}

	return &MonadSignature{
		Signature:   sig,
		Version:     snapshot.Version,
		Dimensions:  len(snapshot.Vector),
		NumHashes:   g.numHashes,
		GeneratedAt: time.Now(),
	}
}

// SimilarityEstimate estimates the cosine similarity between two MonadSignatures
// based on their Hamming distance.
//
// The relationship between Hamming distance and angle is:
//
//	cos(θ) ≈ 1 - 2h/n
//
// where h is the Hamming distance and n is the number of bits.
//
// Returns 0 if other is nil or signatures have different sizes.
// Returns values in the range [-1, 1]:
//   - 1.0: identical vectors (0 Hamming distance)
//   - 0.0: orthogonal vectors (~50% differing bits)
//   - -1.0: opposite vectors (100% differing bits)
//
// Note: This is an estimate - actual cosine similarity may vary due to LSH's
// probabilistic nature. Use more hash bits for higher accuracy.
func (s *MonadSignature) SimilarityEstimate(other *MonadSignature) float32 {
	if other == nil {
		return 0
	}

	distance := HammingDistance(s.Signature, other.Signature)
	if distance < 0 {
		// Mismatched signature sizes
		return 0
	}

	n := s.Signature.Size
	if n == 0 {
		return 0
	}

	// cos(θ) ≈ 1 - 2h/n
	// This formula comes from the property that random hyperplane LSH
	// preserves angular distance: P(bit differs) = θ/π
	// For cosine similarity: cos(θ) ≈ 1 - 2*(h/n)
	estimate := 1.0 - 2.0*float32(distance)/float32(n)

	return estimate
}

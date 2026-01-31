// Package lsh implements Locality Sensitive Hashing using random hyperplanes.
// LSH enables O(log n) peer discovery by producing similar signatures for
// similar vectors without revealing the raw vector data.
package lsh

import (
	"errors"
	"math"
	"math/bits"
	"math/rand"
)

// ErrDimensionMismatch is returned when the vector dimensions don't match the LSH configuration.
var ErrDimensionMismatch = errors.New("lsh: vector dimensions do not match")

// Signature represents an LSH signature as a packed bitstring.
type Signature struct {
	Bits []byte // packed bitstring
	Size int    // number of bits (may not be multiple of 8)
}

// NewSignature creates a new signature with the specified number of bits.
func NewSignature(numBits int) Signature {
	numBytes := (numBits + 7) / 8 // ceiling division
	return Signature{
		Bits: make([]byte, numBytes),
		Size: numBits,
	}
}

// SetBit sets or clears the bit at the given index.
func (s *Signature) SetBit(index int, value bool) {
	if index < 0 || index >= s.Size {
		return
	}

	byteIndex := index / 8
	bitIndex := uint(index % 8)

	if value {
		s.Bits[byteIndex] |= 1 << bitIndex
	} else {
		s.Bits[byteIndex] &^= 1 << bitIndex
	}
}

// GetBit returns the bit value at the given index.
func (s *Signature) GetBit(index int) bool {
	if index < 0 || index >= s.Size {
		return false
	}

	byteIndex := index / 8
	bitIndex := uint(index % 8)

	return (s.Bits[byteIndex] & (1 << bitIndex)) != 0
}

// LSH implements random hyperplane locality sensitive hashing.
type LSH struct {
	numHashes   int         // number of hash functions (bits in signature)
	dimensions  int         // vector dimensions
	hyperplanes [][]float32 // random hyperplanes (unit vectors)
}

// New creates a new LSH with deterministic hyperplanes generated from the seed.
func New(numHashes, dimensions int, seed int64) *LSH {
	rng := rand.New(rand.NewSource(seed))

	hyperplanes := make([][]float32, numHashes)
	for i := 0; i < numHashes; i++ {
		hyperplanes[i] = generateRandomUnitVector(dimensions, rng)
	}

	return &LSH{
		numHashes:   numHashes,
		dimensions:  dimensions,
		hyperplanes: hyperplanes,
	}
}

// generateRandomUnitVector creates a random unit vector of the given dimension.
// Uses normally distributed components and normalizes to ensure uniform distribution
// on the unit sphere.
func generateRandomUnitVector(dimensions int, rng *rand.Rand) []float32 {
	vector := make([]float32, dimensions)
	var sumSq float64

	for i := 0; i < dimensions; i++ {
		// Use normal distribution for uniform distribution on sphere
		val := float32(rng.NormFloat64())
		vector[i] = val
		sumSq += float64(val * val)
	}

	// Normalize to unit length
	norm := float32(math.Sqrt(sumSq))
	if norm > 0 {
		for i := range vector {
			vector[i] /= norm
		}
	}

	return vector
}

// Hash computes the LSH signature for the given vector.
// Returns ErrDimensionMismatch if the vector dimensions don't match.
func (l *LSH) Hash(vector []float32) (Signature, error) {
	if vector == nil || len(vector) != l.dimensions {
		return Signature{}, ErrDimensionMismatch
	}

	sig := NewSignature(l.numHashes)

	for i, hyperplane := range l.hyperplanes {
		dotProduct := dot(vector, hyperplane)
		// bit = 1 if dot(vector, hyperplane) >= 0, else 0
		if dotProduct >= 0 {
			sig.SetBit(i, true)
		}
	}

	return sig, nil
}

// dot computes the dot product of two vectors.
func dot(a, b []float32) float32 {
	if len(a) != len(b) {
		return 0
	}

	var sum float32
	for i := range a {
		sum += a[i] * b[i]
	}
	return sum
}

// HammingDistance counts the number of differing bits between two signatures.
// Returns -1 if the signatures have different sizes.
func HammingDistance(a, b Signature) int {
	if a.Size != b.Size {
		return -1
	}

	distance := 0
	for i := 0; i < len(a.Bits); i++ {
		// XOR bytes and count set bits (differing bits)
		xored := a.Bits[i] ^ b.Bits[i]
		distance += bits.OnesCount8(xored)
	}

	return distance
}

// NumHashes returns the number of hash functions (bits in signature).
func (l *LSH) NumHashes() int {
	return l.numHashes
}

// Dimensions returns the expected vector dimensions.
func (l *LSH) Dimensions() int {
	return l.dimensions
}

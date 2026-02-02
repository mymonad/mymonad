// Package tee provides a mock Trusted Execution Environment for testing.
// In production, this would interface with Intel SGX or another TEE.
package tee

import (
	"fmt"
	"math"
	"unsafe"
)

// CosineSimilarity computes the cosine similarity between two vectors.
// Returns a value between -1 and 1, where 1 means identical direction,
// 0 means orthogonal, and -1 means opposite direction.
func CosineSimilarity(a, b []float32) (float32, error) {
	if len(a) != len(b) {
		return 0, fmt.Errorf("vector length mismatch: %d vs %d", len(a), len(b))
	}
	if len(a) == 0 {
		return 0, fmt.Errorf("vectors cannot be empty")
	}

	var dotProduct float64
	var magnitudeA float64
	var magnitudeB float64

	for i := 0; i < len(a); i++ {
		dotProduct += float64(a[i]) * float64(b[i])
		magnitudeA += float64(a[i]) * float64(a[i])
		magnitudeB += float64(b[i]) * float64(b[i])
	}

	magnitudeA = math.Sqrt(magnitudeA)
	magnitudeB = math.Sqrt(magnitudeB)

	if magnitudeA == 0 || magnitudeB == 0 {
		return 0, fmt.Errorf("cannot compute similarity for zero vector")
	}

	return float32(dotProduct / (magnitudeA * magnitudeB)), nil
}

// ComputeMatch computes whether two monads match above a threshold.
// This is a mock TEE operation - in production, this would run inside SGX.
// Only the boolean result is returned, not the actual similarity score.
func ComputeMatch(localMonad, peerMonad []byte, threshold float32) (bool, error) {
	// Deserialize monads from bytes to float32 slices
	localVec, err := DeserializeMonad(localMonad)
	if err != nil {
		return false, fmt.Errorf("failed to deserialize local monad: %w", err)
	}

	peerVec, err := DeserializeMonad(peerMonad)
	if err != nil {
		return false, fmt.Errorf("failed to deserialize peer monad: %w", err)
	}

	// Compute similarity
	similarity, err := CosineSimilarity(localVec, peerVec)
	if err != nil {
		return false, fmt.Errorf("failed to compute similarity: %w", err)
	}

	// Return only the boolean result, not the score
	// This is the privacy-preserving aspect of the TEE
	return similarity >= threshold, nil
}

// SerializeMonad converts a float32 slice to bytes.
// Uses little-endian encoding for each float32.
func SerializeMonad(values []float32) []byte {
	buf := make([]byte, len(values)*4)
	for i, v := range values {
		bits := *(*uint32)(unsafe.Pointer(&v))
		buf[i*4] = byte(bits)
		buf[i*4+1] = byte(bits >> 8)
		buf[i*4+2] = byte(bits >> 16)
		buf[i*4+3] = byte(bits >> 24)
	}
	return buf
}

// DeserializeMonad converts bytes back to a float32 slice.
// Expects little-endian encoded float32 values.
func DeserializeMonad(data []byte) ([]float32, error) {
	if len(data)%4 != 0 {
		return nil, fmt.Errorf("invalid monad data: length %d not divisible by 4", len(data))
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("monad data cannot be empty")
	}

	result := make([]float32, len(data)/4)
	for i := 0; i < len(result); i++ {
		bits := uint32(data[i*4]) |
			uint32(data[i*4+1])<<8 |
			uint32(data[i*4+2])<<16 |
			uint32(data[i*4+3])<<24
		result[i] = *(*float32)(unsafe.Pointer(&bits))
	}
	return result, nil
}

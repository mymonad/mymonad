// Package zkproof provides zero-knowledge proof functionality for privacy-preserving
// Hamming distance verification.
package zkproof

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewProver tests that NewProver creates a valid Prover instance.
func TestNewProver(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)
	require.NotNil(t, prover)
}

// TestGenerateProof_ValidSignatures tests proof generation with valid signatures
// within the distance threshold.
func TestGenerateProof_ValidSignatures(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)

	// Create two 32-byte signatures with known Hamming distance
	mySignature := make([]byte, 32)
	peerSignature := make([]byte, 32)

	// Set first 3 bytes different (24 bits max)
	peerSignature[0] = 0xFF // 8 bits different
	peerSignature[1] = 0x0F // 4 bits different
	peerSignature[2] = 0x03 // 2 bits different
	// Total: 14 bits different, well within threshold 64

	result, err := prover.GenerateProof(mySignature, peerSignature, 64)
	require.NoError(t, err, "GenerateProof should succeed for signatures within threshold")
	require.NotNil(t, result)

	// Verify proof is non-empty
	assert.NotEmpty(t, result.Proof, "proof should not be empty")

	// Verify commitment is non-empty
	assert.NotEmpty(t, result.Commitment, "commitment should not be empty")

	// Verify public inputs
	assert.Equal(t, result.Commitment, result.PublicInputs.Commitment)
	assert.Equal(t, peerSignature, result.PublicInputs.PeerSignature)
	assert.Equal(t, uint32(64), result.PublicInputs.MaxDistance)
}

// TestGenerateProof_ExceededThreshold tests that proof generation fails when
// the Hamming distance exceeds the threshold.
func TestGenerateProof_ExceededThreshold(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)

	// Create signatures with large Hamming distance (> 64)
	mySignature := make([]byte, 32)
	peerSignature := make([]byte, 32)

	// Set all bytes different: 256 bits different
	for i := range peerSignature {
		peerSignature[i] = 0xFF
	}

	// Try with threshold 64 (should fail - distance is 256)
	result, err := prover.GenerateProof(mySignature, peerSignature, 64)
	assert.Error(t, err, "GenerateProof should fail when distance exceeds threshold")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrDistanceExceedsThreshold)
}

// TestGenerateProof_ExactThreshold tests proof generation when Hamming distance
// exactly equals the threshold (boundary case).
func TestGenerateProof_ExactThreshold(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)

	// Create signatures with exactly 64 bits different
	mySignature := make([]byte, 32)
	peerSignature := make([]byte, 32)

	// Set first 8 bytes to 0xFF (8 * 8 = 64 bits)
	for i := 0; i < 8; i++ {
		peerSignature[i] = 0xFF
	}

	// Threshold 64 should succeed
	result, err := prover.GenerateProof(mySignature, peerSignature, 64)
	require.NoError(t, err, "GenerateProof should succeed when distance equals threshold")
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Proof)
}

// TestGenerateProof_OneOverThreshold tests proof generation when Hamming distance
// is one more than the threshold (boundary case).
func TestGenerateProof_OneOverThreshold(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)

	// Create signatures with exactly 65 bits different
	mySignature := make([]byte, 32)
	peerSignature := make([]byte, 32)

	// Set first 8 bytes to 0xFF (64 bits) + 1 more bit
	for i := 0; i < 8; i++ {
		peerSignature[i] = 0xFF
	}
	peerSignature[8] = 0x01 // 1 more bit

	// Threshold 64 should fail
	result, err := prover.GenerateProof(mySignature, peerSignature, 64)
	assert.Error(t, err, "GenerateProof should fail when distance is one over threshold")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrDistanceExceedsThreshold)
}

// TestGenerateProof_ZeroDistance tests proof generation when signatures are identical.
func TestGenerateProof_ZeroDistance(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)

	// Create identical signatures
	mySignature := make([]byte, 32)
	for i := range mySignature {
		mySignature[i] = byte(i * 7) // Some pattern
	}
	peerSignature := make([]byte, 32)
	copy(peerSignature, mySignature)

	result, err := prover.GenerateProof(mySignature, peerSignature, 64)
	require.NoError(t, err, "GenerateProof should succeed for identical signatures")
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Proof)
}

// TestGenerateProof_InvalidMySignatureLength tests error handling for invalid signature length.
func TestGenerateProof_InvalidMySignatureLength(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)

	// Invalid signature length
	mySignature := make([]byte, 16) // Should be 32
	peerSignature := make([]byte, 32)

	result, err := prover.GenerateProof(mySignature, peerSignature, 64)
	assert.Error(t, err, "GenerateProof should fail for invalid signature length")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrInvalidSignatureLength)
}

// TestGenerateProof_InvalidPeerSignatureLength tests error handling for invalid peer signature length.
func TestGenerateProof_InvalidPeerSignatureLength(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)

	mySignature := make([]byte, 32)
	peerSignature := make([]byte, 16) // Should be 32

	result, err := prover.GenerateProof(mySignature, peerSignature, 64)
	assert.Error(t, err, "GenerateProof should fail for invalid peer signature length")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrInvalidSignatureLength)
}

// TestGenerateProof_CommitmentDeterminism tests that the same signature always
// produces the same commitment.
func TestGenerateProof_CommitmentDeterminism(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)

	// Create signatures with low Hamming distance (within threshold 64)
	mySignature := make([]byte, 32)
	mySignature[0] = 0x0F // Some pattern
	mySignature[1] = 0x55
	peerSignature := make([]byte, 32)
	// peerSignature is all zeros, distance is ~10 bits

	result1, err := prover.GenerateProof(mySignature, peerSignature, 64)
	require.NoError(t, err)

	result2, err := prover.GenerateProof(mySignature, peerSignature, 64)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(result1.Commitment, result2.Commitment),
		"same signature should produce same commitment")
}

// TestGenerateProof_DifferentSignaturesDifferentCommitments tests that different
// signatures produce different commitments.
func TestGenerateProof_DifferentSignaturesDifferentCommitments(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)

	mySignature1 := make([]byte, 32)
	mySignature2 := make([]byte, 32)
	mySignature2[0] = 0x01 // Just one bit different

	peerSignature := make([]byte, 32)

	result1, err := prover.GenerateProof(mySignature1, peerSignature, 64)
	require.NoError(t, err)

	result2, err := prover.GenerateProof(mySignature2, peerSignature, 64)
	require.NoError(t, err)

	assert.False(t, bytes.Equal(result1.Commitment, result2.Commitment),
		"different signatures should produce different commitments")
}

// TestGenerateProof_ProofSerialization tests that the proof is properly serialized.
func TestGenerateProof_ProofSerialization(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)

	mySignature := make([]byte, 32)
	peerSignature := make([]byte, 32)
	peerSignature[0] = 0x0F // 4 bits different

	result, err := prover.GenerateProof(mySignature, peerSignature, 64)
	require.NoError(t, err)

	// Proof should be a reasonable size (PLONK proofs are typically a few hundred bytes)
	assert.Greater(t, len(result.Proof), 100, "proof should be at least 100 bytes")
	assert.Less(t, len(result.Proof), 10000, "proof should be less than 10KB")
}

// TestProver_ConcurrentProofGeneration tests thread safety of proof generation.
func TestProver_ConcurrentProofGeneration(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)

	done := make(chan struct{})
	errors := make(chan error, 5)

	for i := 0; i < 5; i++ {
		go func(idx int) {
			mySignature := make([]byte, 32)
			mySignature[0] = byte(idx) // Different signature for each goroutine

			peerSignature := make([]byte, 32)

			result, err := prover.GenerateProof(mySignature, peerSignature, 64)
			if err != nil {
				errors <- err
				return
			}
			if result == nil || len(result.Proof) == 0 {
				errors <- assert.AnError
				return
			}
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < 5; i++ {
		select {
		case <-done:
			// Success
		case err := <-errors:
			t.Errorf("concurrent proof generation failed: %v", err)
		}
	}
}

// BenchmarkGenerateProof measures proof generation time.
func BenchmarkGenerateProof(b *testing.B) {
	compiled, err := GetCompiledCircuit()
	if err != nil {
		b.Fatal(err)
	}

	prover := NewProver(compiled)

	mySignature := make([]byte, 32)
	peerSignature := make([]byte, 32)
	peerSignature[0] = 0x0F

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := prover.GenerateProof(mySignature, peerSignature, 64)
		if err != nil {
			b.Fatal(err)
		}
	}
}

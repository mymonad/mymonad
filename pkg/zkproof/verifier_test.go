// Package zkproof provides zero-knowledge proof functionality for privacy-preserving
// Hamming distance verification.
package zkproof

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewVerifier tests that NewVerifier creates a valid Verifier instance.
func TestNewVerifier(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	verifier := NewVerifier(compiled)
	require.NotNil(t, verifier)
}

// TestVerifyProof_ValidProof tests that VerifyProof accepts a valid proof.
func TestVerifyProof_ValidProof(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)
	verifier := NewVerifier(compiled)

	// Create two 32-byte signatures with known Hamming distance
	mySignature := make([]byte, 32)
	peerSignature := make([]byte, 32)

	// Set first 2 bytes different (16 bits max)
	peerSignature[0] = 0xFF // 8 bits different
	peerSignature[1] = 0x0F // 4 bits different
	// Total: 12 bits different, well within threshold 64

	// Generate proof
	result, err := prover.GenerateProof(mySignature, peerSignature, 64)
	require.NoError(t, err, "GenerateProof should succeed")

	// Verify the proof
	err = verifier.VerifyProof(result.Proof, result.Commitment, peerSignature, 64)
	assert.NoError(t, err, "VerifyProof should accept valid proof")
}

// TestVerifyProof_ZeroDistance tests verification with identical signatures.
func TestVerifyProof_ZeroDistance(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)
	verifier := NewVerifier(compiled)

	// Create identical signatures
	mySignature := make([]byte, 32)
	for i := range mySignature {
		mySignature[i] = byte(i * 7)
	}
	peerSignature := make([]byte, 32)
	copy(peerSignature, mySignature)

	// Generate proof
	result, err := prover.GenerateProof(mySignature, peerSignature, 64)
	require.NoError(t, err)

	// Verify the proof
	err = verifier.VerifyProof(result.Proof, result.Commitment, peerSignature, 64)
	assert.NoError(t, err, "VerifyProof should accept proof for identical signatures")
}

// TestVerifyProof_ExactThreshold tests verification at exact threshold boundary.
func TestVerifyProof_ExactThreshold(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)
	verifier := NewVerifier(compiled)

	// Create signatures with exactly 64 bits different
	mySignature := make([]byte, 32)
	peerSignature := make([]byte, 32)

	// Set first 8 bytes to 0xFF (8 * 8 = 64 bits)
	for i := 0; i < 8; i++ {
		peerSignature[i] = 0xFF
	}

	// Generate proof
	result, err := prover.GenerateProof(mySignature, peerSignature, 64)
	require.NoError(t, err)

	// Verify the proof
	err = verifier.VerifyProof(result.Proof, result.Commitment, peerSignature, 64)
	assert.NoError(t, err, "VerifyProof should accept proof at exact threshold")
}

// TestVerifyProof_TamperedProof tests that verification rejects tampered proofs.
func TestVerifyProof_TamperedProof(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)
	verifier := NewVerifier(compiled)

	mySignature := make([]byte, 32)
	peerSignature := make([]byte, 32)
	peerSignature[0] = 0x0F

	// Generate valid proof
	result, err := prover.GenerateProof(mySignature, peerSignature, 64)
	require.NoError(t, err)

	// Tamper with the proof by flipping bits
	tamperedProof := make([]byte, len(result.Proof))
	copy(tamperedProof, result.Proof)
	// Flip some bits in the middle of the proof
	if len(tamperedProof) > 50 {
		tamperedProof[50] ^= 0xFF
		tamperedProof[51] ^= 0xFF
	}

	// Verification should fail with tampered proof
	err = verifier.VerifyProof(tamperedProof, result.Commitment, peerSignature, 64)
	assert.Error(t, err, "VerifyProof should reject tampered proof")
}

// TestVerifyProof_WrongPeerSignature tests that verification rejects wrong peer signature.
func TestVerifyProof_WrongPeerSignature(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)
	verifier := NewVerifier(compiled)

	mySignature := make([]byte, 32)
	peerSignature := make([]byte, 32)
	peerSignature[0] = 0x0F

	// Generate proof
	result, err := prover.GenerateProof(mySignature, peerSignature, 64)
	require.NoError(t, err)

	// Use wrong peer signature for verification
	wrongPeerSignature := make([]byte, 32)
	wrongPeerSignature[0] = 0xFF // Different from original

	// Verification should fail with wrong peer signature
	err = verifier.VerifyProof(result.Proof, result.Commitment, wrongPeerSignature, 64)
	assert.Error(t, err, "VerifyProof should reject wrong peer signature")
}

// TestVerifyProof_WrongCommitment tests that verification rejects wrong commitment.
func TestVerifyProof_WrongCommitment(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)
	verifier := NewVerifier(compiled)

	mySignature := make([]byte, 32)
	peerSignature := make([]byte, 32)
	peerSignature[0] = 0x0F

	// Generate proof
	result, err := prover.GenerateProof(mySignature, peerSignature, 64)
	require.NoError(t, err)

	// Generate wrong commitment from different signature
	differentSignature := make([]byte, 32)
	differentSignature[0] = 0xFF
	wrongCommitment, err := ComputeCommitmentFromBytes(differentSignature)
	require.NoError(t, err)
	wrongCommitmentBytes := wrongCommitment.Bytes()

	// Verification should fail with wrong commitment
	err = verifier.VerifyProof(result.Proof, wrongCommitmentBytes, peerSignature, 64)
	assert.Error(t, err, "VerifyProof should reject wrong commitment")
}

// TestVerifyProof_WrongMaxDistance tests that verification rejects wrong max distance.
func TestVerifyProof_WrongMaxDistance(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)
	verifier := NewVerifier(compiled)

	mySignature := make([]byte, 32)
	peerSignature := make([]byte, 32)
	peerSignature[0] = 0x0F

	// Generate proof with threshold 64
	result, err := prover.GenerateProof(mySignature, peerSignature, 64)
	require.NoError(t, err)

	// Try to verify with different threshold
	err = verifier.VerifyProof(result.Proof, result.Commitment, peerSignature, 32)
	assert.Error(t, err, "VerifyProof should reject wrong max distance")
}

// TestVerifyProof_InvalidProofBytes tests that verification handles invalid proof bytes.
func TestVerifyProof_InvalidProofBytes(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	verifier := NewVerifier(compiled)

	peerSignature := make([]byte, 32)
	commitment := make([]byte, 32)

	// Invalid proof bytes (too short)
	invalidProof := []byte{0x01, 0x02, 0x03}

	err = verifier.VerifyProof(invalidProof, commitment, peerSignature, 64)
	assert.Error(t, err, "VerifyProof should reject invalid proof bytes")
}

// TestVerifyProof_EmptyProof tests that verification handles empty proof.
func TestVerifyProof_EmptyProof(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	verifier := NewVerifier(compiled)

	peerSignature := make([]byte, 32)
	commitment := make([]byte, 32)

	err = verifier.VerifyProof([]byte{}, commitment, peerSignature, 64)
	assert.Error(t, err, "VerifyProof should reject empty proof")
}

// TestVerifyProof_InvalidPeerSignatureLength tests error handling for invalid peer signature.
func TestVerifyProof_InvalidPeerSignatureLength(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)
	verifier := NewVerifier(compiled)

	mySignature := make([]byte, 32)
	peerSignature := make([]byte, 32)

	// Generate valid proof
	result, err := prover.GenerateProof(mySignature, peerSignature, 64)
	require.NoError(t, err)

	// Try to verify with wrong peer signature length
	wrongLengthPeerSig := make([]byte, 16) // Should be 32

	err = verifier.VerifyProof(result.Proof, result.Commitment, wrongLengthPeerSig, 64)
	assert.Error(t, err, "VerifyProof should reject invalid peer signature length")
	assert.ErrorIs(t, err, ErrInvalidSignatureLength)
}

// TestVerifier_ConcurrentVerification tests thread safety of proof verification.
func TestVerifier_ConcurrentVerification(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)

	prover := NewProver(compiled)
	verifier := NewVerifier(compiled)

	// Generate a valid proof first
	mySignature := make([]byte, 32)
	peerSignature := make([]byte, 32)
	peerSignature[0] = 0x0F

	result, err := prover.GenerateProof(mySignature, peerSignature, 64)
	require.NoError(t, err)

	done := make(chan struct{})
	errors := make(chan error, 5)

	for i := 0; i < 5; i++ {
		go func() {
			err := verifier.VerifyProof(result.Proof, result.Commitment, peerSignature, 64)
			if err != nil {
				errors <- err
				return
			}
			done <- struct{}{}
		}()
	}

	for i := 0; i < 5; i++ {
		select {
		case <-done:
			// Success
		case err := <-errors:
			t.Errorf("concurrent verification failed: %v", err)
		}
	}
}

// BenchmarkVerifyProof measures proof verification time.
func BenchmarkVerifyProof(b *testing.B) {
	compiled, err := GetCompiledCircuit()
	if err != nil {
		b.Fatal(err)
	}

	prover := NewProver(compiled)
	verifier := NewVerifier(compiled)

	mySignature := make([]byte, 32)
	peerSignature := make([]byte, 32)
	peerSignature[0] = 0x0F

	result, err := prover.GenerateProof(mySignature, peerSignature, 64)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := verifier.VerifyProof(result.Proof, result.Commitment, peerSignature, 64)
		if err != nil {
			b.Fatal(err)
		}
	}
}

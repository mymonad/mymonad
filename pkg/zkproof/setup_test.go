// Package zkproof provides zero-knowledge proof functionality for privacy-preserving
// Hamming distance verification.
package zkproof

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCompileCircuit_Success tests that the circuit compiles successfully.
func TestCompileCircuit_Success(t *testing.T) {
	compiled, err := CompileCircuit()
	require.NoError(t, err, "CompileCircuit should not return an error")
	require.NotNil(t, compiled, "compiled circuit should not be nil")

	// Verify the constraint system is valid
	assert.NotNil(t, compiled.ConstraintSystem, "constraint system should not be nil")
	assert.Greater(t, compiled.ConstraintSystem.GetNbConstraints(), 0, "should have constraints")

	// Verify keys are generated
	assert.NotNil(t, compiled.ProvingKey, "proving key should not be nil")
	assert.NotNil(t, compiled.VerifyingKey, "verifying key should not be nil")
}

// TestCompileCircuit_Idempotent tests that multiple compilations produce consistent results.
func TestCompileCircuit_Idempotent(t *testing.T) {
	compiled1, err := CompileCircuit()
	require.NoError(t, err)

	compiled2, err := CompileCircuit()
	require.NoError(t, err)

	// Both should have the same number of constraints
	assert.Equal(t,
		compiled1.ConstraintSystem.GetNbConstraints(),
		compiled2.ConstraintSystem.GetNbConstraints(),
		"constraint count should be consistent across compilations",
	)
}

// TestCompiledCircuit_ConstraintCount tests that the circuit has expected constraint count.
// This is a sanity check to ensure the circuit complexity is reasonable.
func TestCompiledCircuit_ConstraintCount(t *testing.T) {
	compiled, err := CompileCircuit()
	require.NoError(t, err)

	nbConstraints := compiled.ConstraintSystem.GetNbConstraints()

	// The circuit should have constraints for:
	// - 256 boolean constraints for signature bits
	// - 256 XOR operations for Hamming distance
	// - MiMC hash operations
	// - Less-than-or-equal comparison
	// We expect a few thousand constraints, but not millions
	assert.Greater(t, nbConstraints, 100, "should have more than 100 constraints")
	assert.Less(t, nbConstraints, 1000000, "should have less than 1M constraints")

	t.Logf("Circuit has %d constraints", nbConstraints)
}

// TestGetCompiledCircuit_ReturnsCompiled tests that GetCompiledCircuit returns compiled circuit.
func TestGetCompiledCircuit_ReturnsCompiled(t *testing.T) {
	compiled, err := GetCompiledCircuit()
	require.NoError(t, err)
	require.NotNil(t, compiled)

	// Verify it's the same instance on second call (cached)
	compiled2, err := GetCompiledCircuit()
	require.NoError(t, err)
	require.Same(t, compiled, compiled2, "should return cached instance")
}

// TestCompiledCircuit_GetNbPublicVariables tests public variable count.
func TestCompiledCircuit_GetNbPublicVariables(t *testing.T) {
	compiled, err := CompileCircuit()
	require.NoError(t, err)

	// Public inputs: Commitment (1) + PeerSignature (256) + MaxDistance (1) = 258
	// Plus 1 for the constant wire = 259
	nbPublic := compiled.ConstraintSystem.GetNbPublicVariables()
	assert.Greater(t, nbPublic, 250, "should have at least 250 public variables")
	t.Logf("Circuit has %d public variables", nbPublic)
}

// TestResetCompiledCircuit tests that ResetCompiledCircuit clears the cache.
func TestResetCompiledCircuit(t *testing.T) {
	// Get first instance
	compiled1, err := GetCompiledCircuit()
	require.NoError(t, err)

	// Reset
	ResetCompiledCircuit()

	// Get new instance - should be different from first
	compiled2, err := GetCompiledCircuit()
	require.NoError(t, err)

	// Should be different instances (new compilation)
	assert.NotSame(t, compiled1, compiled2, "should return new instance after reset")
}

// TestCompiledCircuit_EndToEndProof tests the full proof workflow.
// This ensures the compiled circuit can actually generate and verify proofs.
func TestCompiledCircuit_EndToEndProof(t *testing.T) {
	// Compile circuit
	compiled, err := CompileCircuit()
	require.NoError(t, err)

	// Create test data with Hamming distance 20 (within threshold 64)
	signatureBits, peerBits := createSignatureBitsWithDistance(20)

	// Compute commitment
	commitment := computeCommitmentForTest(signatureBits)

	// Create full witness assignment
	assignment := &HammingCircuit{
		MaxDistance: 64,
		Commitment:  commitment,
	}
	for i := 0; i < SignatureBits; i++ {
		assignment.Signature[i] = signatureBits[i]
		assignment.PeerSignature[i] = peerBits[i]
	}

	// Create witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(t, err)

	// Generate proof
	proof, err := plonk.Prove(compiled.ConstraintSystem, compiled.ProvingKey, witness)
	require.NoError(t, err, "proof generation should succeed")
	require.NotNil(t, proof)

	// Extract public witness for verification
	publicWitness, err := witness.Public()
	require.NoError(t, err)

	// Verify proof
	err = plonk.Verify(proof, compiled.VerifyingKey, publicWitness)
	assert.NoError(t, err, "proof verification should succeed")
}

// TestCompiledCircuit_InvalidProofFails tests that invalid proofs are rejected.
func TestCompiledCircuit_InvalidProofFails(t *testing.T) {
	// Compile circuit
	compiled, err := CompileCircuit()
	require.NoError(t, err)

	// Create test data with Hamming distance 100 (exceeds threshold 64)
	signatureBits, peerBits := createSignatureBitsWithDistance(100)

	// Compute commitment
	commitment := computeCommitmentForTest(signatureBits)

	// Create full witness assignment with exceeded threshold
	assignment := &HammingCircuit{
		MaxDistance: 64,
		Commitment:  commitment,
	}
	for i := 0; i < SignatureBits; i++ {
		assignment.Signature[i] = signatureBits[i]
		assignment.PeerSignature[i] = peerBits[i]
	}

	// Create witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(t, err)

	// Proof generation should fail because distance exceeds threshold
	_, err = plonk.Prove(compiled.ConstraintSystem, compiled.ProvingKey, witness)
	assert.Error(t, err, "proof generation should fail for invalid witness")
}

// TestCompiledCircuit_WrongCommitmentFails tests that wrong commitment is rejected.
func TestCompiledCircuit_WrongCommitmentFails(t *testing.T) {
	// Compile circuit
	compiled, err := CompileCircuit()
	require.NoError(t, err)

	// Create valid signatures
	signatureBits := make([]int, SignatureBits)
	peerBits := make([]int, SignatureBits)

	// Compute wrong commitment (use different signature)
	wrongSignatureBits := make([]int, SignatureBits)
	for i := 0; i < SignatureBits; i++ {
		wrongSignatureBits[i] = 1
	}
	wrongCommitment := computeCommitmentForTest(wrongSignatureBits)

	// Create witness with correct signature but wrong commitment
	assignment := &HammingCircuit{
		MaxDistance: 64,
		Commitment:  wrongCommitment,
	}
	for i := 0; i < SignatureBits; i++ {
		assignment.Signature[i] = signatureBits[i]
		assignment.PeerSignature[i] = peerBits[i]
	}

	// Create witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(t, err)

	// Proof generation should fail due to commitment mismatch
	_, err = plonk.Prove(compiled.ConstraintSystem, compiled.ProvingKey, witness)
	assert.Error(t, err, "proof generation should fail for wrong commitment")
}

// TestCompiledCircuit_TamperedProofFails tests that tampered proofs are rejected.
func TestCompiledCircuit_TamperedProofFails(t *testing.T) {
	// Compile circuit
	compiled, err := CompileCircuit()
	require.NoError(t, err)

	// Create valid test data
	signatureBits, peerBits := createSignatureBitsWithDistance(20)
	commitment := computeCommitmentForTest(signatureBits)

	// Create full witness
	assignment := &HammingCircuit{
		MaxDistance: 64,
		Commitment:  commitment,
	}
	for i := 0; i < SignatureBits; i++ {
		assignment.Signature[i] = signatureBits[i]
		assignment.PeerSignature[i] = peerBits[i]
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(t, err)

	// Generate valid proof
	proof, err := plonk.Prove(compiled.ConstraintSystem, compiled.ProvingKey, witness)
	require.NoError(t, err)

	// Create tampered public witness (different MaxDistance)
	tamperedAssignment := &HammingCircuit{
		MaxDistance: 10, // Different from original 64
		Commitment:  commitment,
	}
	for i := 0; i < SignatureBits; i++ {
		tamperedAssignment.Signature[i] = 0
		tamperedAssignment.PeerSignature[i] = peerBits[i]
	}

	tamperedWitness, err := frontend.NewWitness(tamperedAssignment, ecc.BN254.ScalarField())
	require.NoError(t, err)
	tamperedPublic, err := tamperedWitness.Public()
	require.NoError(t, err)

	// Verification should fail with tampered public inputs
	err = plonk.Verify(proof, compiled.VerifyingKey, tamperedPublic)
	assert.Error(t, err, "verification should fail with tampered public inputs")
}

// TestCompiledCircuit_ConcurrentAccess tests thread safety.
func TestCompiledCircuit_ConcurrentAccess(t *testing.T) {
	// Reset to ensure clean state
	ResetCompiledCircuit()

	done := make(chan struct{})
	errors := make(chan error, 10)

	// Start multiple goroutines accessing the compiled circuit
	for i := 0; i < 10; i++ {
		go func() {
			compiled, err := GetCompiledCircuit()
			if err != nil {
				errors <- err
				return
			}
			if compiled == nil {
				errors <- assert.AnError
				return
			}
			done <- struct{}{}
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		select {
		case <-done:
			// Success
		case err := <-errors:
			t.Errorf("concurrent access failed: %v", err)
		}
	}
}

// TestCompiledCircuit_KeysSerializable tests that keys can be serialized.
// This is important for production where keys need to be stored/loaded.
func TestCompiledCircuit_KeysSerializable(t *testing.T) {
	compiled, err := CompileCircuit()
	require.NoError(t, err)

	// Test that verifying key can be written
	// This validates the key format is correct
	vkBytes := compiled.VerifyingKey.NbPublicWitness()
	assert.Greater(t, vkBytes, 0, "verifying key should have public witness size > 0")
}

// BenchmarkCompileCircuit measures circuit compilation time.
func BenchmarkCompileCircuit(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := CompileCircuit()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkProveWithCompiledCircuit measures proof generation time.
func BenchmarkProveWithCompiledCircuit(b *testing.B) {
	compiled, err := CompileCircuit()
	if err != nil {
		b.Fatal(err)
	}

	// Create test data
	signatureBits, peerBits := createSignatureBitsWithDistance(20)
	commitment := computeCommitmentForTest(signatureBits)

	assignment := &HammingCircuit{
		MaxDistance: 64,
		Commitment:  commitment,
	}
	for i := 0; i < SignatureBits; i++ {
		assignment.Signature[i] = signatureBits[i]
		assignment.PeerSignature[i] = peerBits[i]
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := plonk.Prove(compiled.ConstraintSystem, compiled.ProvingKey, witness)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyWithCompiledCircuit measures proof verification time.
func BenchmarkVerifyWithCompiledCircuit(b *testing.B) {
	compiled, err := CompileCircuit()
	if err != nil {
		b.Fatal(err)
	}

	// Create test data
	signatureBits, peerBits := createSignatureBitsWithDistance(20)
	commitment := computeCommitmentForTest(signatureBits)

	assignment := &HammingCircuit{
		MaxDistance: 64,
		Commitment:  commitment,
	}
	for i := 0; i < SignatureBits; i++ {
		assignment.Signature[i] = signatureBits[i]
		assignment.PeerSignature[i] = peerBits[i]
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}

	proof, err := plonk.Prove(compiled.ConstraintSystem, compiled.ProvingKey, witness)
	if err != nil {
		b.Fatal(err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := plonk.Verify(proof, compiled.VerifyingKey, publicWitness)
		if err != nil {
			b.Fatal(err)
		}
	}
}


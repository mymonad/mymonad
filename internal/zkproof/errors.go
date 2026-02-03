// Package zkproof provides zero-knowledge proof functionality.
//
// This file defines error types for the ZK proof system.
// All errors implement the standard error interface and can be used
// with errors.Is() and errors.As() for error matching.
package zkproof

// ZKError represents a categorized error in the ZK proof system.
// Using a string type allows for easy serialization and comparison
// while providing a clear error message.
type ZKError string

// ZK proof error constants.
// These errors cover the main failure modes of the ZK proof system.
const (
	// ErrProofGenerationFailed indicates that proof generation failed.
	// This can occur due to invalid inputs, circuit constraints violations,
	// or internal errors in the proving system.
	ErrProofGenerationFailed ZKError = "proof_generation_failed"

	// ErrProofVerificationFailed indicates that proof verification failed.
	// This occurs when the PLONK proof does not verify against the public inputs.
	ErrProofVerificationFailed ZKError = "proof_verification_failed"

	// ErrCommitmentMismatch indicates that the proof's commitment doesn't match.
	// This occurs when the prover's commitment in the proof differs from
	// the commitment they advertised.
	ErrCommitmentMismatch ZKError = "commitment_mismatch"

	// ErrThresholdExceeded indicates that the Hamming distance exceeds the limit.
	// This occurs when the signatures are too different to satisfy the
	// agreed-upon distance threshold.
	ErrThresholdExceeded ZKError = "threshold_exceeded"

	// ErrIncompatibleSystem indicates incompatible proof systems between peers.
	// This occurs when peers use different proving systems (e.g., plonk vs groth16)
	// or different curves (e.g., bn254 vs bls12-381).
	ErrIncompatibleSystem ZKError = "incompatible_proof_system"

	// ErrProofTimeout indicates that a proof operation timed out.
	// This occurs when proof generation or verification takes longer than
	// the configured timeout.
	ErrProofTimeout ZKError = "proof_timeout"

	// ErrCircuitNotReady indicates that the circuit has not been compiled.
	// This occurs when attempting to generate or verify proofs before
	// the circuit compilation is complete.
	ErrCircuitNotReady ZKError = "circuit_not_compiled"
)

// Error implements the error interface for ZKError.
// This allows ZKError values to be used anywhere an error is expected.
func (e ZKError) Error() string {
	return string(e)
}

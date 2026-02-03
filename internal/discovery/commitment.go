// Package discovery provides peer discovery mechanisms for the P2P network.
// The commitment scheme ensures fair exchange of LSH signatures by requiring
// peers to commit to their signature before seeing the other party's signature.
package discovery

import (
	"crypto/sha256"
	"crypto/subtle"
)

// DiscoveryError represents errors that can occur during the discovery protocol.
// Error string values match protobuf reason codes exactly for serialization.
type DiscoveryError string

const (
	// ErrCommitmentMismatch indicates the revealed signature and salt
	// do not match the previously provided commitment.
	ErrCommitmentMismatch DiscoveryError = "commitment_mismatch"

	// ErrStaleTimestamp indicates the message timestamp is too old or in the future.
	ErrStaleTimestamp DiscoveryError = "stale_timestamp"

	// ErrInvalidSalt indicates the salt is too short (minimum 16 bytes required).
	ErrInvalidSalt DiscoveryError = "invalid_salt"

	// ErrMalformedSignature indicates the signature has an invalid length
	// (expected 32 bytes for 256-bit LSH signatures).
	ErrMalformedSignature DiscoveryError = "malformed_signature"

	// ErrRateLimited indicates the peer has exceeded the allowed request rate.
	ErrRateLimited DiscoveryError = "rate_limited"
)

// Error implements the error interface for DiscoveryError.
func (e DiscoveryError) Error() string {
	return string(e)
}

// Commitment-related constants
const (
	// MinSaltLength is the minimum required salt length in bytes.
	// 16 bytes (128 bits) provides sufficient randomness to prevent
	// precomputation attacks on the commitment scheme.
	MinSaltLength = 16

	// ExpectedSignatureLength is the expected length of LSH signatures in bytes.
	// 32 bytes (256 bits) matches our LSH configuration.
	ExpectedSignatureLength = 32

	// CommitmentLength is the length of the commitment hash in bytes.
	// SHA-256 produces 32-byte (256-bit) output.
	CommitmentLength = 32
)

// computeCommitment generates SHA-256(signature || salt).
// This creates a binding commitment that hides the signature until the salt is revealed.
func computeCommitment(signature, salt []byte) []byte {
	h := sha256.New()
	h.Write(signature)
	h.Write(salt)
	return h.Sum(nil)
}

// verifyCommitment checks if the commitment matches the signature and salt.
// It validates input lengths and performs constant-time comparison to prevent timing attacks.
//
// Returns nil if verification succeeds, or one of:
//   - ErrInvalidSalt: salt is less than MinSaltLength bytes
//   - ErrMalformedSignature: signature is not ExpectedSignatureLength bytes
//   - ErrCommitmentMismatch: computed commitment does not match provided commitment
func verifyCommitment(commitment, signature, salt []byte) error {
	// Validate salt length (minimum 16 bytes)
	if len(salt) < MinSaltLength {
		return ErrInvalidSalt
	}

	// Validate signature length (expected 32 bytes for 256-bit LSH)
	if len(signature) != ExpectedSignatureLength {
		return ErrMalformedSignature
	}

	// Compute and compare commitment using constant-time comparison
	// to prevent timing side-channel attacks
	expected := computeCommitment(signature, salt)
	if subtle.ConstantTimeCompare(commitment, expected) != 1 {
		return ErrCommitmentMismatch
	}

	return nil
}

package discovery

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// Helper functions for test data generation
func makeSignature(size int) []byte {
	sig := make([]byte, size)
	rand.Read(sig)
	return sig
}

func makeSalt(size int) []byte {
	salt := make([]byte, size)
	rand.Read(salt)
	return salt
}

// ============================================================
// computeCommitment Tests
// ============================================================

func TestComputeCommitment(t *testing.T) {
	signature := make([]byte, 32)
	salt := make([]byte, 16)
	rand.Read(signature)
	rand.Read(salt)

	commitment := computeCommitment(signature, salt)

	// Should be 32 bytes (SHA-256)
	if len(commitment) != 32 {
		t.Errorf("commitment length: got %d, want 32", len(commitment))
	}
}

func TestComputeCommitmentDeterministic(t *testing.T) {
	signature := make([]byte, 32)
	salt := make([]byte, 16)
	rand.Read(signature)
	rand.Read(salt)

	commitment1 := computeCommitment(signature, salt)
	commitment2 := computeCommitment(signature, salt)

	// Should be deterministic
	if !bytes.Equal(commitment1, commitment2) {
		t.Error("commitment should be deterministic for same inputs")
	}
}

func TestComputeCommitmentDifferentSalt(t *testing.T) {
	signature := make([]byte, 32)
	salt1 := make([]byte, 16)
	salt2 := make([]byte, 16)
	rand.Read(signature)
	rand.Read(salt1)
	rand.Read(salt2)

	commitment1 := computeCommitment(signature, salt1)
	commitment2 := computeCommitment(signature, salt2)

	// Different salt should produce different commitment
	if bytes.Equal(commitment1, commitment2) {
		t.Error("different salts should produce different commitments")
	}
}

func TestComputeCommitmentDifferentSignature(t *testing.T) {
	signature1 := make([]byte, 32)
	signature2 := make([]byte, 32)
	salt := make([]byte, 16)
	rand.Read(signature1)
	rand.Read(signature2)
	rand.Read(salt)

	commitment1 := computeCommitment(signature1, salt)
	commitment2 := computeCommitment(signature2, salt)

	// Different signature should produce different commitment
	if bytes.Equal(commitment1, commitment2) {
		t.Error("different signatures should produce different commitments")
	}
}

func TestComputeCommitmentOrderMatters(t *testing.T) {
	// Ensure commitment is H(signature || salt), not H(salt || signature)
	// Use two different 32-byte values to test order dependency
	sigData := make([]byte, 32)
	saltData := make([]byte, 32)
	rand.Read(sigData)
	rand.Read(saltData)

	// H(sig || salt) should differ from H(salt || sig) when sig != salt
	commitment1 := computeCommitment(sigData, saltData)
	commitment2 := computeCommitment(saltData, sigData) // Swapped order

	// The commitments should be different because input order matters
	if bytes.Equal(commitment1, commitment2) {
		t.Error("commitment should depend on input order (H(A||B) != H(B||A) when A != B)")
	}
}

// ============================================================
// verifyCommitment Tests
// ============================================================

func TestVerifyCommitmentValid(t *testing.T) {
	signature := makeSignature(32)
	salt := makeSalt(16)
	commitment := computeCommitment(signature, salt)

	err := verifyCommitment(commitment, signature, salt)
	if err != nil {
		t.Errorf("valid commitment should verify: %v", err)
	}
}

func TestVerifyCommitmentTampered(t *testing.T) {
	signature := makeSignature(32)
	salt := makeSalt(16)
	commitment := computeCommitment(signature, salt)

	// Tamper with commitment
	commitment[0] ^= 0xFF

	err := verifyCommitment(commitment, signature, salt)
	if err != ErrCommitmentMismatch {
		t.Errorf("tampered commitment should return ErrCommitmentMismatch, got %v", err)
	}
}

func TestVerifyCommitmentSaltTooShort(t *testing.T) {
	signature := makeSignature(32)
	salt := makeSalt(8) // < 16 bytes
	commitment := computeCommitment(signature, salt)

	err := verifyCommitment(commitment, signature, salt)
	if err != ErrInvalidSalt {
		t.Errorf("salt too short should return ErrInvalidSalt, got %v", err)
	}
}

func TestVerifyCommitmentSaltBoundary(t *testing.T) {
	signature := makeSignature(32)

	// Test boundary: 15 bytes should fail
	shortSalt := makeSalt(15)
	shortCommitment := computeCommitment(signature, shortSalt)

	err := verifyCommitment(shortCommitment, signature, shortSalt)
	if err != ErrInvalidSalt {
		t.Errorf("15-byte salt should return ErrInvalidSalt, got %v", err)
	}

	// Test boundary: 16 bytes should pass
	validSalt := makeSalt(16)
	validCommitment := computeCommitment(signature, validSalt)

	err = verifyCommitment(validCommitment, signature, validSalt)
	if err != nil {
		t.Errorf("16-byte salt should be valid, got %v", err)
	}
}

func TestVerifyCommitmentMalformedSignature(t *testing.T) {
	testCases := []struct {
		name    string
		sigSize int
	}{
		{"signature too short (16 bytes)", 16},
		{"signature too short (31 bytes)", 31},
		{"signature too long (33 bytes)", 33},
		{"signature too long (64 bytes)", 64},
		{"empty signature", 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signature := makeSignature(tc.sigSize)
			salt := makeSalt(16)
			commitment := computeCommitment(signature, salt)

			err := verifyCommitment(commitment, signature, salt)
			if err != ErrMalformedSignature {
				t.Errorf("signature of %d bytes should return ErrMalformedSignature, got %v", tc.sigSize, err)
			}
		})
	}
}

func TestVerifyCommitmentWrongSignature(t *testing.T) {
	signature1 := makeSignature(32)
	signature2 := makeSignature(32)
	salt := makeSalt(16)

	// Create commitment with signature1
	commitment := computeCommitment(signature1, salt)

	// Verify with signature2
	err := verifyCommitment(commitment, signature2, salt)
	if err != ErrCommitmentMismatch {
		t.Errorf("wrong signature should return ErrCommitmentMismatch, got %v", err)
	}
}

func TestVerifyCommitmentWrongSalt(t *testing.T) {
	signature := makeSignature(32)
	salt1 := makeSalt(16)
	salt2 := makeSalt(16)

	// Create commitment with salt1
	commitment := computeCommitment(signature, salt1)

	// Verify with salt2
	err := verifyCommitment(commitment, signature, salt2)
	if err != ErrCommitmentMismatch {
		t.Errorf("wrong salt should return ErrCommitmentMismatch, got %v", err)
	}
}

func TestVerifyCommitmentLongerSalt(t *testing.T) {
	// Salt longer than 16 bytes should be accepted
	signature := makeSignature(32)
	salt := makeSalt(32) // 32 bytes > 16 minimum
	commitment := computeCommitment(signature, salt)

	err := verifyCommitment(commitment, signature, salt)
	if err != nil {
		t.Errorf("longer salt should be valid, got %v", err)
	}
}

func TestVerifyCommitmentNilInputs(t *testing.T) {
	t.Run("nil commitment", func(t *testing.T) {
		signature := makeSignature(32)
		salt := makeSalt(16)

		err := verifyCommitment(nil, signature, salt)
		if err != ErrCommitmentMismatch {
			t.Errorf("nil commitment should return ErrCommitmentMismatch, got %v", err)
		}
	})

	t.Run("nil signature", func(t *testing.T) {
		salt := makeSalt(16)
		commitment := computeCommitment(nil, salt)

		err := verifyCommitment(commitment, nil, salt)
		if err != ErrMalformedSignature {
			t.Errorf("nil signature should return ErrMalformedSignature, got %v", err)
		}
	})

	t.Run("nil salt", func(t *testing.T) {
		signature := makeSignature(32)
		commitment := computeCommitment(signature, nil)

		err := verifyCommitment(commitment, signature, nil)
		if err != ErrInvalidSalt {
			t.Errorf("nil salt should return ErrInvalidSalt, got %v", err)
		}
	})
}

// ============================================================
// DiscoveryError Tests
// ============================================================

func TestDiscoveryErrorImplementsError(t *testing.T) {
	var err error = ErrCommitmentMismatch
	if err.Error() != "commitment_mismatch" {
		t.Errorf("ErrCommitmentMismatch.Error(): got %q, want %q", err.Error(), "commitment_mismatch")
	}
}

func TestDiscoveryErrorStrings(t *testing.T) {
	testCases := []struct {
		err      DiscoveryError
		expected string
	}{
		{ErrCommitmentMismatch, "commitment_mismatch"},
		{ErrStaleTimestamp, "stale_timestamp"},
		{ErrInvalidSalt, "invalid_salt"},
		{ErrMalformedSignature, "malformed_signature"},
		{ErrRateLimited, "rate_limited"},
	}

	for _, tc := range testCases {
		t.Run(string(tc.err), func(t *testing.T) {
			if tc.err.Error() != tc.expected {
				t.Errorf("Error() = %q, want %q", tc.err.Error(), tc.expected)
			}
		})
	}
}

// ============================================================
// Security Tests
// ============================================================

func TestCommitmentHidesSignature(t *testing.T) {
	// The commitment should not contain any recognizable part of the signature
	// This is a basic check - SHA-256 provides preimage resistance
	signature := makeSignature(32)
	salt := makeSalt(16)

	commitment := computeCommitment(signature, salt)

	// Commitment should not match signature prefix
	if bytes.HasPrefix(commitment, signature[:8]) {
		t.Error("commitment should not contain signature prefix")
	}
}

func TestCommitmentUniqueness(t *testing.T) {
	// Generate many commitments and ensure they're all unique
	const numCommitments = 100
	commitments := make(map[string]bool)

	for i := 0; i < numCommitments; i++ {
		signature := makeSignature(32)
		salt := makeSalt(16)
		commitment := computeCommitment(signature, salt)

		key := string(commitment)
		if commitments[key] {
			t.Errorf("duplicate commitment found at iteration %d", i)
		}
		commitments[key] = true
	}
}

// ============================================================
// Benchmarks
// ============================================================

func BenchmarkComputeCommitment(b *testing.B) {
	signature := makeSignature(32)
	salt := makeSalt(16)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeCommitment(signature, salt)
	}
}

func BenchmarkVerifyCommitment(b *testing.B) {
	signature := makeSignature(32)
	salt := makeSalt(16)
	commitment := computeCommitment(signature, salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifyCommitment(commitment, signature, salt)
	}
}

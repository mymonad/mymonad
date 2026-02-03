// Package zkproof provides zero-knowledge proof functionality for privacy-preserving
// Hamming distance verification.
package zkproof

import (
	"bytes"
	"testing"
)

func TestComputeCommitment(t *testing.T) {
	t.Run("valid signature", func(t *testing.T) {
		bits := make([]int, SignatureBits)
		for i := 0; i < 20; i++ {
			bits[i] = 1
		}

		commitment, err := ComputeCommitment(bits)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if commitment == nil {
			t.Fatal("commitment should not be nil")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		bits := make([]int, SignatureBits)
		for i := 0; i < 50; i++ {
			bits[i] = 1
		}

		c1, err := ComputeCommitment(bits)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		c2, err := ComputeCommitment(bits)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if c1.Cmp(c2) != 0 {
			t.Fatal("commitment should be deterministic")
		}
	})

	t.Run("different signatures produce different commitments", func(t *testing.T) {
		bits1 := make([]int, SignatureBits)
		bits2 := make([]int, SignatureBits)
		bits2[0] = 1 // Just one bit different

		c1, err := ComputeCommitment(bits1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		c2, err := ComputeCommitment(bits2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if c1.Cmp(c2) == 0 {
			t.Fatal("different signatures should produce different commitments")
		}
	})

	t.Run("invalid length", func(t *testing.T) {
		bits := make([]int, 100) // Wrong length

		_, err := ComputeCommitment(bits)
		if err != ErrInvalidSignatureLength {
			t.Fatalf("expected ErrInvalidSignatureLength, got: %v", err)
		}
	})
}

func TestComputeCommitmentFromBytes(t *testing.T) {
	t.Run("valid signature", func(t *testing.T) {
		signature := make([]byte, 32)
		signature[0] = 0xFF // First 8 bits set

		commitment, err := ComputeCommitmentFromBytes(signature)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if commitment == nil {
			t.Fatal("commitment should not be nil")
		}
	})

	t.Run("matches bit-based commitment", func(t *testing.T) {
		// Create a signature with first 8 bits set
		bits := make([]int, SignatureBits)
		for i := 0; i < 8; i++ {
			bits[i] = 1
		}

		signature := make([]byte, 32)
		signature[0] = 0xFF // First 8 bits set

		c1, err := ComputeCommitment(bits)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		c2, err := ComputeCommitmentFromBytes(signature)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if c1.Cmp(c2) != 0 {
			t.Fatal("commitments should match")
		}
	})

	t.Run("invalid length", func(t *testing.T) {
		signature := make([]byte, 16) // Wrong length

		_, err := ComputeCommitmentFromBytes(signature)
		if err != ErrInvalidSignatureLength {
			t.Fatalf("expected ErrInvalidSignatureLength, got: %v", err)
		}
	})
}

func TestSignatureToBits(t *testing.T) {
	t.Run("converts correctly", func(t *testing.T) {
		signature := make([]byte, 32)
		signature[0] = 0x05 // Bits 0 and 2 set

		bits, err := SignatureToBits(signature)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if bits[0] != 1 {
			t.Error("bit 0 should be 1")
		}
		if bits[1] != 0 {
			t.Error("bit 1 should be 0")
		}
		if bits[2] != 1 {
			t.Error("bit 2 should be 1")
		}
		if bits[3] != 0 {
			t.Error("bit 3 should be 0")
		}
	})

	t.Run("invalid length", func(t *testing.T) {
		signature := make([]byte, 16)

		_, err := SignatureToBits(signature)
		if err != ErrInvalidSignatureLength {
			t.Fatalf("expected ErrInvalidSignatureLength, got: %v", err)
		}
	})
}

func TestBitsToSignature(t *testing.T) {
	t.Run("converts correctly", func(t *testing.T) {
		bits := make([]int, SignatureBits)
		bits[0] = 1
		bits[2] = 1 // Should give 0x05 in first byte

		signature, err := BitsToSignature(bits)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if signature[0] != 0x05 {
			t.Errorf("expected first byte 0x05, got 0x%02X", signature[0])
		}
	})

	t.Run("roundtrip", func(t *testing.T) {
		original := make([]byte, 32)
		for i := range original {
			original[i] = byte(i * 7) // Arbitrary pattern
		}

		bits, err := SignatureToBits(original)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		result, err := BitsToSignature(bits)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !bytes.Equal(original, result) {
			t.Fatal("roundtrip should preserve signature")
		}
	})

	t.Run("invalid length", func(t *testing.T) {
		bits := make([]int, 100)

		_, err := BitsToSignature(bits)
		if err != ErrInvalidSignatureLength {
			t.Fatalf("expected ErrInvalidSignatureLength, got: %v", err)
		}
	})
}

func TestHammingDistanceBits(t *testing.T) {
	t.Run("zero distance", func(t *testing.T) {
		sig1 := make([]int, SignatureBits)
		sig2 := make([]int, SignatureBits)

		distance, err := HammingDistanceBits(sig1, sig2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if distance != 0 {
			t.Errorf("expected distance 0, got %d", distance)
		}
	})

	t.Run("partial distance", func(t *testing.T) {
		sig1 := make([]int, SignatureBits)
		sig2 := make([]int, SignatureBits)
		for i := 0; i < 50; i++ {
			sig2[i] = 1
		}

		distance, err := HammingDistanceBits(sig1, sig2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if distance != 50 {
			t.Errorf("expected distance 50, got %d", distance)
		}
	})

	t.Run("max distance", func(t *testing.T) {
		sig1 := make([]int, SignatureBits)
		sig2 := make([]int, SignatureBits)
		for i := 0; i < SignatureBits; i++ {
			sig2[i] = 1
		}

		distance, err := HammingDistanceBits(sig1, sig2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if distance != SignatureBits {
			t.Errorf("expected distance %d, got %d", SignatureBits, distance)
		}
	})

	t.Run("invalid length", func(t *testing.T) {
		sig1 := make([]int, 100)
		sig2 := make([]int, SignatureBits)

		_, err := HammingDistanceBits(sig1, sig2)
		if err != ErrInvalidSignatureLength {
			t.Fatalf("expected ErrInvalidSignatureLength, got: %v", err)
		}
	})
}

func TestHammingDistanceBytes(t *testing.T) {
	t.Run("zero distance", func(t *testing.T) {
		sig1 := make([]byte, 32)
		sig2 := make([]byte, 32)

		distance, err := HammingDistanceBytes(sig1, sig2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if distance != 0 {
			t.Errorf("expected distance 0, got %d", distance)
		}
	})

	t.Run("partial distance", func(t *testing.T) {
		sig1 := make([]byte, 32)
		sig2 := make([]byte, 32)
		sig2[0] = 0xFF // 8 bits different
		sig2[1] = 0x0F // 4 bits different

		distance, err := HammingDistanceBytes(sig1, sig2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if distance != 12 {
			t.Errorf("expected distance 12, got %d", distance)
		}
	})

	t.Run("max distance", func(t *testing.T) {
		sig1 := make([]byte, 32)
		sig2 := make([]byte, 32)
		for i := range sig2 {
			sig2[i] = 0xFF
		}

		distance, err := HammingDistanceBytes(sig1, sig2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if distance != SignatureBits {
			t.Errorf("expected distance %d, got %d", SignatureBits, distance)
		}
	})

	t.Run("matches bit distance", func(t *testing.T) {
		sigBytes1 := make([]byte, 32)
		sigBytes2 := make([]byte, 32)
		for i := 0; i < 5; i++ {
			sigBytes2[i] = byte(i + 1)
		}

		bits1, _ := SignatureToBits(sigBytes1)
		bits2, _ := SignatureToBits(sigBytes2)

		d1, _ := HammingDistanceBytes(sigBytes1, sigBytes2)
		d2, _ := HammingDistanceBits(bits1, bits2)

		if d1 != d2 {
			t.Errorf("byte and bit distances should match: %d vs %d", d1, d2)
		}
	})

	t.Run("invalid length", func(t *testing.T) {
		sig1 := make([]byte, 16)
		sig2 := make([]byte, 32)

		_, err := HammingDistanceBytes(sig1, sig2)
		if err != ErrInvalidSignatureLength {
			t.Fatalf("expected ErrInvalidSignatureLength, got: %v", err)
		}
	})
}

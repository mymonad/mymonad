// Package zkproof provides zero-knowledge proof functionality.
//
// This file contains tests for ZK capability compatibility checking.
package zkproof

import (
	"errors"
	"testing"

	pb "github.com/mymonad/mymonad/api/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckCompatibility_Compatible(t *testing.T) {
	cap := &ZKCapability{
		Supported:        true,
		ProofSystem:      "plonk-bn254",
		MaxSignatureBits: 256,
	}
	err := CheckCompatibility(cap)
	require.NoError(t, err)
}

func TestCheckCompatibility_WrongProofSystem(t *testing.T) {
	cap := &ZKCapability{
		Supported:        true,
		ProofSystem:      "groth16-bn254",
		MaxSignatureBits: 256,
	}
	err := CheckCompatibility(cap)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrIncompatibleSystem),
		"error should be ErrIncompatibleSystem, got: %v", err)
	assert.Contains(t, err.Error(), "groth16-bn254")
	assert.Contains(t, err.Error(), "plonk-bn254")
}

func TestCheckCompatibility_WrongSignatureBits(t *testing.T) {
	cap := &ZKCapability{
		Supported:        true,
		ProofSystem:      "plonk-bn254",
		MaxSignatureBits: 512,
	}
	err := CheckCompatibility(cap)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature")
	assert.Contains(t, err.Error(), "512")
	assert.Contains(t, err.Error(), "256")
}

func TestCheckCompatibility_NotSupported(t *testing.T) {
	cap := &ZKCapability{
		Supported:        false,
		ProofSystem:      "plonk-bn254",
		MaxSignatureBits: 256,
	}
	err := CheckCompatibility(cap)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not enabled")
}

func TestCheckCompatibility_NilCapability(t *testing.T) {
	err := CheckCompatibility(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no ZK capability")
}

func TestNewZKCapability(t *testing.T) {
	cap := NewZKCapability()

	require.NotNil(t, cap)
	assert.True(t, cap.Supported, "new capability should be supported")
	assert.Equal(t, SupportedProofSystem, cap.ProofSystem,
		"new capability should use supported proof system")
	assert.Equal(t, uint32(SupportedSignatureBits), cap.MaxSignatureBits,
		"new capability should use supported signature bits")
}

func TestZKCapability_ToProto(t *testing.T) {
	cap := &ZKCapability{
		Supported:        true,
		ProofSystem:      "plonk-bn254",
		MaxSignatureBits: 256,
	}

	proto := cap.ToProto()

	require.NotNil(t, proto)
	assert.Equal(t, cap.Supported, proto.Supported)
	assert.Equal(t, cap.ProofSystem, proto.ProofSystem)
	assert.Equal(t, cap.MaxSignatureBits, proto.MaxSignatureBits)
}

func TestZKCapabilityFromProto(t *testing.T) {
	t.Run("valid proto", func(t *testing.T) {
		proto := &pb.ZKCapability{
			Supported:        true,
			ProofSystem:      "plonk-bn254",
			MaxSignatureBits: 256,
		}

		cap := ZKCapabilityFromProto(proto)

		require.NotNil(t, cap)
		assert.Equal(t, proto.Supported, cap.Supported)
		assert.Equal(t, proto.ProofSystem, cap.ProofSystem)
		assert.Equal(t, proto.MaxSignatureBits, cap.MaxSignatureBits)
	})

	t.Run("nil proto", func(t *testing.T) {
		cap := ZKCapabilityFromProto(nil)
		assert.Nil(t, cap)
	})
}

func TestZKCapability_RoundTrip(t *testing.T) {
	// Test that converting to proto and back preserves all fields
	original := &ZKCapability{
		Supported:        true,
		ProofSystem:      "plonk-bn254",
		MaxSignatureBits: 256,
	}

	proto := original.ToProto()
	roundTripped := ZKCapabilityFromProto(proto)

	require.NotNil(t, roundTripped)
	assert.Equal(t, original.Supported, roundTripped.Supported)
	assert.Equal(t, original.ProofSystem, roundTripped.ProofSystem)
	assert.Equal(t, original.MaxSignatureBits, roundTripped.MaxSignatureBits)
}

func TestCheckCompatibility_SelfCompatible(t *testing.T) {
	// Our own capability should always be compatible
	cap := NewZKCapability()
	err := CheckCompatibility(cap)
	require.NoError(t, err, "our own capability should be compatible")
}

// TestZKError verifies error interface implementation
func TestZKError_Interface(t *testing.T) {
	tests := []struct {
		err      ZKError
		expected string
	}{
		{ErrProofGenerationFailed, "proof_generation_failed"},
		{ErrProofVerificationFailed, "proof_verification_failed"},
		{ErrCommitmentMismatch, "commitment_mismatch"},
		{ErrThresholdExceeded, "threshold_exceeded"},
		{ErrIncompatibleSystem, "incompatible_proof_system"},
		{ErrProofTimeout, "proof_timeout"},
		{ErrCircuitNotReady, "circuit_not_compiled"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			// Verify Error() returns the expected string
			assert.Equal(t, tc.expected, tc.err.Error())

			// Verify it implements error interface
			var err error = tc.err
			assert.NotNil(t, err)
		})
	}
}

func TestZKError_Is(t *testing.T) {
	// Test that errors.Is works correctly with ZKError
	err := ErrIncompatibleSystem
	assert.True(t, errors.Is(err, ErrIncompatibleSystem))
	assert.False(t, errors.Is(err, ErrProofGenerationFailed))
}

// Package zkproof provides zero-knowledge proof functionality for privacy-preserving
// Hamming distance verification.
package zkproof

import (
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

var (
	// compiledCircuit is a cached instance of the compiled circuit.
	compiledCircuit *CompiledCircuit
	// compileMu protects concurrent access to compiledCircuit.
	compileMu sync.Mutex
)

// CompiledCircuit contains the compiled constraint system and cryptographic keys
// needed to generate and verify proofs. This is computed once at startup.
type CompiledCircuit struct {
	// ConstraintSystem is the compiled circuit in sparse constraint form.
	ConstraintSystem constraint.ConstraintSystem

	// ProvingKey is used to generate proofs.
	ProvingKey plonk.ProvingKey

	// VerifyingKey is used to verify proofs.
	VerifyingKey plonk.VerifyingKey
}

// CompileCircuit compiles the HammingCircuit and generates proving/verifying keys.
// This is a computationally expensive operation and should only be done once at startup.
//
// The function uses PlonK with BN254 curve for efficient proof generation and verification.
// It uses an unsafe SRS (Structured Reference String) suitable for development and testing.
// For production use, a proper trusted setup ceremony should be conducted.
func CompileCircuit() (*CompiledCircuit, error) {
	// Define circuit structure (no witness values needed for compilation)
	var circuit HammingCircuit

	// Compile to sparse constraint system (SCS) for PlonK
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		return nil, fmt.Errorf("compile circuit: %w", err)
	}

	// Generate SRS (Structured Reference String) for the given constraint count
	// Note: unsafekzg.NewSRS is for development/testing only.
	// Production systems should use a properly generated SRS from a trusted setup ceremony.
	srs, srsLagrange, err := unsafekzg.NewSRS(cs)
	if err != nil {
		return nil, fmt.Errorf("generate SRS: %w", err)
	}

	// Generate proving and verifying keys
	pk, vk, err := plonk.Setup(cs, srs, srsLagrange)
	if err != nil {
		return nil, fmt.Errorf("setup keys: %w", err)
	}

	return &CompiledCircuit{
		ConstraintSystem: cs,
		ProvingKey:       pk,
		VerifyingKey:     vk,
	}, nil
}

// GetCompiledCircuit returns a cached compiled circuit, compiling it on first call.
// This is thread-safe and returns the same instance for all callers.
func GetCompiledCircuit() (*CompiledCircuit, error) {
	compileMu.Lock()
	defer compileMu.Unlock()

	if compiledCircuit != nil {
		return compiledCircuit, nil
	}

	compiled, err := CompileCircuit()
	if err != nil {
		return nil, err
	}

	compiledCircuit = compiled
	return compiledCircuit, nil
}

// ResetCompiledCircuit clears the cached compiled circuit.
// This is mainly useful for testing.
func ResetCompiledCircuit() {
	compileMu.Lock()
	defer compileMu.Unlock()
	compiledCircuit = nil
}

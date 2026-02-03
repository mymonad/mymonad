// Package zkproof provides zero-knowledge proof functionality for privacy-preserving
// Hamming distance verification.
package zkproof

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
)

// Verifier validates zero-knowledge proofs for Hamming distance verification.
// It verifies that a prover knows a signature S such that:
// 1. Commitment(S) = C (the publicly announced commitment)
// 2. HammingDistance(S, S_peer) <= k (threshold)
type Verifier struct {
	compiled *CompiledCircuit
}

// NewVerifier creates a new Verifier with the given compiled circuit.
func NewVerifier(compiled *CompiledCircuit) *Verifier {
	return &Verifier{compiled: compiled}
}

// VerifyProof validates a ZK proof of Hamming distance bound.
//
// The verifier checks that the proof demonstrates knowledge of a signature that:
// 1. Has the given commitment
// 2. Is within maxDistance of the given peer signature
//
// Parameters:
//   - proofBytes: The serialized PLONK proof
//   - proverCommitment: The MiMC hash commitment from the prover
//   - peerSignature: The verifier's 32-byte signature (the one the prover claims to be close to)
//   - maxDistance: The maximum allowed Hamming distance threshold
//
// Returns:
//   - nil if the proof is valid
//   - Error if proof verification fails
func (v *Verifier) VerifyProof(
	proofBytes []byte,
	proverCommitment []byte,
	peerSignature []byte,
	maxDistance uint32,
) error {
	// Validate peer signature length
	if len(peerSignature) != SignatureBits/8 {
		return fmt.Errorf("%w: peer signature has %d bytes, expected %d",
			ErrInvalidSignatureLength, len(peerSignature), SignatureBits/8)
	}

	// Deserialize the proof
	proof := plonk.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return fmt.Errorf("deserialize proof: %w", err)
	}

	// Build public witness (verifier only knows public inputs)
	publicWitness, err := v.buildPublicWitness(proverCommitment, peerSignature, maxDistance)
	if err != nil {
		return fmt.Errorf("build public witness: %w", err)
	}

	// Verify the proof
	if err := plonk.Verify(proof, v.compiled.VerifyingKey, publicWitness); err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}

	return nil
}

// buildPublicWitness constructs the public witness for verification.
// The public witness contains only the public inputs (not the secret signature).
func (v *Verifier) buildPublicWitness(
	commitment []byte,
	peerSignature []byte,
	maxDistance uint32,
) (witness.Witness, error) {
	var circuit HammingCircuit

	// Set public inputs only (no private signature)
	circuit.Commitment = new(big.Int).SetBytes(commitment)

	// Set peer signature bits
	for i := 0; i < SignatureBits; i++ {
		byteIdx := i / 8
		bitIdx := i % 8
		bit := (peerSignature[byteIdx] >> bitIdx) & 1
		circuit.PeerSignature[i] = bit
	}

	circuit.MaxDistance = maxDistance

	// Create public-only witness (for verification, not proving)
	return frontend.NewWitness(&circuit, ecc.BN254.ScalarField(), frontend.PublicOnly())
}

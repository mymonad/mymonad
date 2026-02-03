// Package zkproof provides zero-knowledge proof functionality for privacy-preserving
// Hamming distance verification.
package zkproof

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
)

var (
	// ErrDistanceExceedsThreshold is returned when the Hamming distance between
	// signatures exceeds the specified threshold.
	ErrDistanceExceedsThreshold = errors.New("zkproof: hamming distance exceeds threshold")
)

// Prover generates zero-knowledge proofs for Hamming distance verification.
// It proves that the prover knows a signature S such that:
// 1. Commitment(S) = C (publicly announced commitment)
// 2. HammingDistance(S, S_peer) <= k (threshold)
type Prover struct {
	compiled *CompiledCircuit
}

// ProofResult contains the generated proof and associated public data.
type ProofResult struct {
	// Proof is the serialized zero-knowledge proof.
	Proof []byte

	// Commitment is the MiMC hash of the prover's signature.
	// This is revealed publicly to allow verification without revealing the signature.
	Commitment []byte

	// PublicInputs contains the public inputs used in the proof.
	PublicInputs PublicInputs
}

// PublicInputs contains the public inputs for proof verification.
type PublicInputs struct {
	// Commitment is the MiMC hash of the prover's signature.
	Commitment []byte

	// PeerSignature is the peer's signature (publicly known).
	PeerSignature []byte

	// MaxDistance is the maximum allowed Hamming distance threshold.
	MaxDistance uint32
}

// NewProver creates a new Prover with the given compiled circuit.
func NewProver(compiled *CompiledCircuit) *Prover {
	return &Prover{compiled: compiled}
}

// GenerateProof creates a ZK proof that the prover's signature is within
// the specified Hamming distance threshold of the peer's signature.
//
// The proof demonstrates knowledge of mySignature without revealing it, by:
// 1. Computing a commitment to mySignature using MiMC hash
// 2. Proving that HammingDistance(mySignature, peerSignature) <= maxDistance
//
// Parameters:
//   - mySignature: The prover's 32-byte (256-bit) LSH signature (kept private)
//   - peerSignature: The peer's 32-byte signature (public)
//   - maxDistance: The maximum allowed Hamming distance threshold
//
// Returns:
//   - ProofResult containing the serialized proof and public inputs
//   - Error if proof generation fails (e.g., distance exceeds threshold)
func (p *Prover) GenerateProof(
	mySignature []byte,
	peerSignature []byte,
	maxDistance uint32,
) (*ProofResult, error) {
	// Validate input lengths
	if len(mySignature) != SignatureBits/8 {
		return nil, fmt.Errorf("%w: my signature has %d bytes, expected %d",
			ErrInvalidSignatureLength, len(mySignature), SignatureBits/8)
	}
	if len(peerSignature) != SignatureBits/8 {
		return nil, fmt.Errorf("%w: peer signature has %d bytes, expected %d",
			ErrInvalidSignatureLength, len(peerSignature), SignatureBits/8)
	}

	// Check Hamming distance before attempting proof generation
	// This provides a clear error message and avoids expensive failed proof attempts
	distance, err := HammingDistanceBytes(mySignature, peerSignature)
	if err != nil {
		return nil, fmt.Errorf("compute distance: %w", err)
	}
	if distance > int(maxDistance) {
		return nil, fmt.Errorf("%w: distance %d exceeds threshold %d",
			ErrDistanceExceedsThreshold, distance, maxDistance)
	}

	// Compute commitment to our signature using MiMC hash
	commitment, err := ComputeCommitmentFromBytes(mySignature)
	if err != nil {
		return nil, fmt.Errorf("compute commitment: %w", err)
	}

	// Build the witness for the circuit
	witness, err := p.buildWitness(mySignature, peerSignature, commitment, maxDistance)
	if err != nil {
		return nil, fmt.Errorf("build witness: %w", err)
	}

	// Generate the proof using PLONK
	proof, err := plonk.Prove(p.compiled.ConstraintSystem, p.compiled.ProvingKey, witness)
	if err != nil {
		return nil, fmt.Errorf("generate proof: %w", err)
	}

	// Serialize the proof
	var proofBuf bytes.Buffer
	if _, err := proof.WriteTo(&proofBuf); err != nil {
		return nil, fmt.Errorf("serialize proof: %w", err)
	}

	// Serialize commitment to bytes
	commitmentBytes := commitment.Bytes()

	return &ProofResult{
		Proof:      proofBuf.Bytes(),
		Commitment: commitmentBytes,
		PublicInputs: PublicInputs{
			Commitment:    commitmentBytes,
			PeerSignature: peerSignature,
			MaxDistance:   maxDistance,
		},
	}, nil
}

// buildWitness constructs the witness for the HammingCircuit.
// The witness contains both private (signature) and public (commitment, peer signature, threshold) values.
func (p *Prover) buildWitness(
	signature, peerSignature []byte,
	commitment *big.Int,
	maxDistance uint32,
) (witness.Witness, error) {
	var circuit HammingCircuit

	// Set private witness (signature bits)
	// Convert bytes to individual bits in the same order as the commitment computation
	for i := 0; i < SignatureBits; i++ {
		byteIdx := i / 8
		bitIdx := i % 8
		bit := (signature[byteIdx] >> bitIdx) & 1
		circuit.Signature[i] = bit
	}

	// Set public inputs
	circuit.Commitment = commitment

	// Set peer signature bits
	for i := 0; i < SignatureBits; i++ {
		byteIdx := i / 8
		bitIdx := i % 8
		bit := (peerSignature[byteIdx] >> bitIdx) & 1
		circuit.PeerSignature[i] = bit
	}

	circuit.MaxDistance = maxDistance

	// Create the full witness (includes both private and public values)
	return frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
}

// Package zkproof provides zero-knowledge proof functionality for privacy-preserving
// Hamming distance verification. It implements a ZK circuit that proves:
//
// "I know a signature S such that Commitment(S) = C and HammingDistance(S, S_peer) <= k"
//
// This enables privacy-preserving peer matching without revealing actual signatures.
package zkproof

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

const (
	// SignatureBits is the length of LSH signatures in bits.
	SignatureBits = 256

	// PackedElements is the number of field elements needed to pack the signature.
	// 256 bits / 64 bits per element = 4 elements.
	PackedElements = 4

	// BitsPerElement is the number of bits packed into each field element.
	BitsPerElement = 64
)

// HammingCircuit proves Hamming distance bound without revealing signature.
// It verifies that:
// 1. The prover's signature matches the public commitment
// 2. The Hamming distance between prover's and peer's signatures is within threshold
type HammingCircuit struct {
	// Private witness (prover's secret)
	Signature [SignatureBits]frontend.Variable `gnark:",secret"`

	// Public inputs
	Commitment    frontend.Variable                 `gnark:",public"` // Hash of prover's signature
	PeerSignature [SignatureBits]frontend.Variable `gnark:",public"`
	MaxDistance   frontend.Variable                 `gnark:",public"` // Threshold k
}

// Define implements frontend.Circuit and specifies the circuit constraints.
// It enforces:
// 1. All signature bits are boolean (0 or 1)
// 2. The commitment matches MiMC(packed signature)
// 3. Hamming distance between signatures is <= MaxDistance
func (c *HammingCircuit) Define(api frontend.API) error {
	// 1. Verify commitment matches signature
	if err := c.verifyCommitment(api); err != nil {
		return err
	}

	// 2. Compute Hamming distance
	distance := c.computeHammingDistance(api)

	// 3. Assert distance <= threshold
	api.AssertIsLessOrEqual(distance, c.MaxDistance)

	return nil
}

// verifyCommitment verifies that the commitment matches the hash of the signature.
// This prevents the prover from claiming a different signature than committed.
func (c *HammingCircuit) verifyCommitment(api frontend.API) error {
	// Pack signature bits into field elements for hashing
	packed := c.packSignature(api)

	// MiMC hash (SNARK-friendly)
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	for _, p := range packed {
		h.Write(p)
	}

	computedCommitment := h.Sum()
	api.AssertIsEqual(computedCommitment, c.Commitment)

	return nil
}

// packSignature packs 256 signature bits into 4 x 64-bit field elements.
// Each bit is constrained to be boolean (0 or 1) via the Xor operation.
func (c *HammingCircuit) packSignature(api frontend.API) []frontend.Variable {
	packed := make([]frontend.Variable, PackedElements)

	for i := 0; i < PackedElements; i++ {
		var acc frontend.Variable = 0
		for j := 0; j < BitsPerElement; j++ {
			bitIdx := i*BitsPerElement + j

			// Constrain bit to be boolean
			api.AssertIsBoolean(c.Signature[bitIdx])

			// Compute 2^j * bit
			coefficient := uint64(1) << j
			shifted := api.Mul(c.Signature[bitIdx], coefficient)
			acc = api.Add(acc, shifted)
		}
		packed[i] = acc
	}

	return packed
}

// computeHammingDistance computes the Hamming distance between the prover's
// signature and the peer's signature. The distance is the number of differing bits.
func (c *HammingCircuit) computeHammingDistance(api frontend.API) frontend.Variable {
	var distance frontend.Variable = 0

	for i := 0; i < SignatureBits; i++ {
		// XOR: different bits produce 1
		// api.Xor constrains both inputs to be boolean
		xor := api.Xor(c.Signature[i], c.PeerSignature[i])

		// Accumulate
		distance = api.Add(distance, xor)
	}

	return distance
}

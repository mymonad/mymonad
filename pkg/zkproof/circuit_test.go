// Package zkproof provides zero-knowledge proof functionality for privacy-preserving
// Hamming distance verification.
package zkproof

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/test"
)

// packSignatureBits packs 256 signature bits into 4 x 64-bit big.Int values.
// This matches the circuit's packSignature logic.
func packSignatureBits(bits []int) []*big.Int {
	packed := make([]*big.Int, 4)

	for i := 0; i < 4; i++ {
		acc := big.NewInt(0)
		for j := 0; j < 64; j++ {
			bitIdx := i*64 + j
			if bits[bitIdx] == 1 {
				shift := big.NewInt(1)
				shift.Lsh(shift, uint(j))
				acc.Add(acc, shift)
			}
		}
		packed[i] = acc
	}

	return packed
}

// computeCommitmentForTest computes the MiMC commitment for a signature.
// Uses gnark-crypto's native MiMC for BN254.
func computeCommitmentForTest(bits []int) *big.Int {
	packed := packSignatureBits(bits)

	// Convert to field elements
	var elems []fr.Element
	for _, p := range packed {
		var elem fr.Element
		elem.SetBigInt(p)
		elems = append(elems, elem)
	}

	// Compute MiMC hash
	h := mimc.NewMiMC()
	for _, elem := range elems {
		b := elem.Bytes()
		h.Write(b[:])
	}

	var result fr.Element
	result.SetBytes(h.Sum(nil))

	return result.BigInt(new(big.Int))
}

// createWitness creates a HammingCircuit witness with the given parameters.
func createWitness(signatureBits, peerBits []int, maxDistance int, commitment *big.Int) *HammingCircuit {
	witness := &HammingCircuit{
		MaxDistance: maxDistance,
		Commitment:  commitment,
	}

	for i := 0; i < SignatureBits; i++ {
		witness.Signature[i] = signatureBits[i]
		witness.PeerSignature[i] = peerBits[i]
	}

	return witness
}

// createSignatureBitsWithDistance creates two bit slices with a specific Hamming distance.
// The first is all zeros, the second has 'distance' bits set to 1.
func createSignatureBitsWithDistance(distance int) ([]int, []int) {
	sig1 := make([]int, SignatureBits)
	sig2 := make([]int, SignatureBits)

	for i := 0; i < SignatureBits; i++ {
		sig1[i] = 0
		if i < distance {
			sig2[i] = 1
		} else {
			sig2[i] = 0
		}
	}

	return sig1, sig2
}

// TestHammingCircuit_ValidProof tests that a valid proof succeeds.
// Two signatures with Hamming distance 20, threshold 64 - should succeed.
func TestHammingCircuit_ValidProof(t *testing.T) {
	assert := test.NewAssert(t)

	// Create two signatures with Hamming distance 20 (within threshold 64)
	signatureBits, peerBits := createSignatureBitsWithDistance(20)

	// Compute the correct commitment for the signature
	commitment := computeCommitmentForTest(signatureBits)

	// Create witness
	witness := createWitness(signatureBits, peerBits, 64, commitment)

	// Create circuit definition
	var circuit HammingCircuit

	assert.ProverSucceeded(&circuit, witness, test.WithCurves(ecc.BN254))
}

// TestHammingCircuit_RejectsExceededThreshold tests that proof fails when distance exceeds threshold.
// Two signatures with Hamming distance 100, threshold 64 - should fail.
func TestHammingCircuit_RejectsExceededThreshold(t *testing.T) {
	assert := test.NewAssert(t)

	// Create two signatures with Hamming distance 100 (exceeds threshold 64)
	signatureBits, peerBits := createSignatureBitsWithDistance(100)

	// Compute the correct commitment
	commitment := computeCommitmentForTest(signatureBits)

	// Create witness
	witness := createWitness(signatureBits, peerBits, 64, commitment)

	// Create circuit definition
	var circuit HammingCircuit

	assert.ProverFailed(&circuit, witness, test.WithCurves(ecc.BN254))
}

// TestHammingCircuit_RejectsWrongCommitment tests that proof fails with wrong commitment.
// Correct signature, wrong commitment - should fail.
func TestHammingCircuit_RejectsWrongCommitment(t *testing.T) {
	assert := test.NewAssert(t)

	// Create two identical signatures (distance 0)
	signatureBits := make([]int, SignatureBits)
	peerBits := make([]int, SignatureBits)
	for i := 0; i < SignatureBits; i++ {
		signatureBits[i] = 0
		peerBits[i] = 0
	}

	// Create a different signature for computing wrong commitment
	wrongSignatureBits := make([]int, SignatureBits)
	for i := 0; i < SignatureBits; i++ {
		wrongSignatureBits[i] = 1 // All ones instead of all zeros
	}

	// Compute commitment for wrong signature
	wrongCommitment := computeCommitmentForTest(wrongSignatureBits)

	// Create witness with correct signature but wrong commitment
	witness := createWitness(signatureBits, peerBits, 64, wrongCommitment)

	// Create circuit definition
	var circuit HammingCircuit

	assert.ProverFailed(&circuit, witness, test.WithCurves(ecc.BN254))
}

// TestHammingCircuit_EdgeCaseExactThreshold tests exact threshold boundary.
// Hamming distance exactly 64, threshold 64 - should succeed (<=).
func TestHammingCircuit_EdgeCaseExactThreshold(t *testing.T) {
	assert := test.NewAssert(t)

	// Create two signatures with Hamming distance exactly 64
	signatureBits, peerBits := createSignatureBitsWithDistance(64)

	// Compute the correct commitment
	commitment := computeCommitmentForTest(signatureBits)

	// Create witness
	witness := createWitness(signatureBits, peerBits, 64, commitment)

	// Create circuit definition
	var circuit HammingCircuit

	assert.ProverSucceeded(&circuit, witness, test.WithCurves(ecc.BN254))
}

// TestHammingCircuit_EdgeCaseOneOverThreshold tests one over threshold.
// Hamming distance 65, threshold 64 - should fail.
func TestHammingCircuit_EdgeCaseOneOverThreshold(t *testing.T) {
	assert := test.NewAssert(t)

	// Create two signatures with Hamming distance 65 (one over threshold)
	signatureBits, peerBits := createSignatureBitsWithDistance(65)

	// Compute the correct commitment
	commitment := computeCommitmentForTest(signatureBits)

	// Create witness
	witness := createWitness(signatureBits, peerBits, 64, commitment)

	// Create circuit definition
	var circuit HammingCircuit

	assert.ProverFailed(&circuit, witness, test.WithCurves(ecc.BN254))
}

// TestHammingCircuit_ZeroDistance tests that identical signatures pass.
func TestHammingCircuit_ZeroDistance(t *testing.T) {
	assert := test.NewAssert(t)

	// Create two identical signatures (distance 0)
	signatureBits, _ := createSignatureBitsWithDistance(0)
	peerBits := make([]int, SignatureBits) // Same as signatureBits (all zeros)
	copy(peerBits, signatureBits)

	// Compute the correct commitment
	commitment := computeCommitmentForTest(signatureBits)

	// Create witness
	witness := createWitness(signatureBits, peerBits, 64, commitment)

	// Create circuit definition
	var circuit HammingCircuit

	assert.ProverSucceeded(&circuit, witness, test.WithCurves(ecc.BN254))
}

// TestHammingCircuit_MaxDistance tests maximum possible distance.
func TestHammingCircuit_MaxDistance(t *testing.T) {
	assert := test.NewAssert(t)

	// Create two signatures with maximum Hamming distance (256)
	signatureBits := make([]int, SignatureBits)
	peerBits := make([]int, SignatureBits)
	for i := 0; i < SignatureBits; i++ {
		signatureBits[i] = 0
		peerBits[i] = 1 // All bits differ
	}

	// Compute the correct commitment
	commitment := computeCommitmentForTest(signatureBits)

	// Create witness with threshold allowing max distance
	witness := createWitness(signatureBits, peerBits, 256, commitment)

	// Create circuit definition
	var circuit HammingCircuit

	assert.ProverSucceeded(&circuit, witness, test.WithCurves(ecc.BN254))
}

// TestHammingCircuit_NonBinaryBitsFail tests that non-binary values fail.
// The circuit should constrain signature bits to be boolean.
func TestHammingCircuit_NonBinaryBitsFail(t *testing.T) {
	assert := test.NewAssert(t)

	// Create valid signatures
	signatureBits := make([]int, SignatureBits)
	peerBits := make([]int, SignatureBits)
	for i := 0; i < SignatureBits; i++ {
		signatureBits[i] = 0
		peerBits[i] = 0
	}

	// Compute the correct commitment
	commitment := computeCommitmentForTest(signatureBits)

	// Create circuit definition
	var circuit HammingCircuit

	// Create witness with a non-binary value (2 instead of 0 or 1)
	witness := &HammingCircuit{
		MaxDistance: 64,
		Commitment:  commitment,
	}
	for i := 0; i < SignatureBits; i++ {
		if i == 0 {
			witness.Signature[i] = 2 // Non-binary value!
		} else {
			witness.Signature[i] = signatureBits[i]
		}
		witness.PeerSignature[i] = peerBits[i]
	}

	assert.ProverFailed(&circuit, witness, test.WithCurves(ecc.BN254))
}

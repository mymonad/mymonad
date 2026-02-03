// Package zkproof provides zero-knowledge proof functionality for privacy-preserving
// Hamming distance verification.
package zkproof

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

var (
	// ErrInvalidSignatureLength is returned when the signature has wrong length.
	ErrInvalidSignatureLength = errors.New("zkproof: invalid signature length")
)

// ComputeCommitment computes the MiMC commitment for a 256-bit signature.
// This is used outside the circuit to create commitments for public announcements.
// The signature should be provided as a slice of 256 bits (0 or 1 values).
func ComputeCommitment(signatureBits []int) (*big.Int, error) {
	if len(signatureBits) != SignatureBits {
		return nil, ErrInvalidSignatureLength
	}

	// Pack bits into 4 x 64-bit field elements
	packed := packBits(signatureBits)

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

	return result.BigInt(new(big.Int)), nil
}

// ComputeCommitmentFromBytes computes the MiMC commitment from a packed byte signature.
// The signature should be 32 bytes (256 bits).
func ComputeCommitmentFromBytes(signature []byte) (*big.Int, error) {
	if len(signature) != SignatureBits/8 {
		return nil, ErrInvalidSignatureLength
	}

	// Unpack bytes to bits
	bits := make([]int, SignatureBits)
	for i := 0; i < len(signature); i++ {
		for j := 0; j < 8; j++ {
			bitIdx := i*8 + j
			if (signature[i] & (1 << j)) != 0 {
				bits[bitIdx] = 1
			}
		}
	}

	return ComputeCommitment(bits)
}

// SignatureToBits converts a packed byte signature to a bit slice.
// The signature should be 32 bytes (256 bits).
func SignatureToBits(signature []byte) ([]int, error) {
	if len(signature) != SignatureBits/8 {
		return nil, ErrInvalidSignatureLength
	}

	bits := make([]int, SignatureBits)
	for i := 0; i < len(signature); i++ {
		for j := 0; j < 8; j++ {
			bitIdx := i*8 + j
			if (signature[i] & (1 << j)) != 0 {
				bits[bitIdx] = 1
			}
		}
	}

	return bits, nil
}

// BitsToSignature converts a bit slice to a packed byte signature.
// The bits slice should have 256 elements.
func BitsToSignature(bits []int) ([]byte, error) {
	if len(bits) != SignatureBits {
		return nil, ErrInvalidSignatureLength
	}

	signature := make([]byte, SignatureBits/8)
	for i := 0; i < SignatureBits; i++ {
		if bits[i] == 1 {
			byteIdx := i / 8
			bitIdx := i % 8
			signature[byteIdx] |= 1 << bitIdx
		}
	}

	return signature, nil
}

// packBits packs 256 bits into 4 x 64-bit big.Int values.
func packBits(bits []int) []*big.Int {
	packed := make([]*big.Int, PackedElements)

	for i := 0; i < PackedElements; i++ {
		acc := big.NewInt(0)
		for j := 0; j < BitsPerElement; j++ {
			bitIdx := i*BitsPerElement + j
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

// HammingDistanceBits computes the Hamming distance between two bit signatures.
// Both signatures should have 256 bits.
func HammingDistanceBits(sig1, sig2 []int) (int, error) {
	if len(sig1) != SignatureBits || len(sig2) != SignatureBits {
		return 0, ErrInvalidSignatureLength
	}

	distance := 0
	for i := 0; i < SignatureBits; i++ {
		if sig1[i] != sig2[i] {
			distance++
		}
	}

	return distance, nil
}

// HammingDistanceBytes computes the Hamming distance between two byte signatures.
// Both signatures should be 32 bytes.
func HammingDistanceBytes(sig1, sig2 []byte) (int, error) {
	if len(sig1) != SignatureBits/8 || len(sig2) != SignatureBits/8 {
		return 0, ErrInvalidSignatureLength
	}

	distance := 0
	for i := 0; i < len(sig1); i++ {
		xored := sig1[i] ^ sig2[i]
		for xored != 0 {
			distance += int(xored & 1)
			xored >>= 1
		}
	}

	return distance, nil
}

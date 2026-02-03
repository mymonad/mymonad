// Package zkproof provides zero-knowledge proof functionality.
//
// This file handles ZK capability compatibility checking between peers.
// Peers must have compatible ZK configurations to exchange proofs successfully.
package zkproof

import (
	"fmt"

	pb "github.com/mymonad/mymonad/api/proto"
)

// Supported ZK proof system parameters.
// These define the proof system this implementation supports.
const (
	// SupportedProofSystem is the proof system identifier.
	// Currently we support PLONK proofs on the BN254 curve.
	SupportedProofSystem = "plonk-bn254"

	// SupportedSignatureBits is the LSH signature length in bits.
	// This matches the circuit's expected input size.
	SupportedSignatureBits = 256
)

// ZKCapability represents a peer's ZK proof capability.
// This is exchanged during peer discovery to determine protocol compatibility.
type ZKCapability struct {
	// Supported indicates whether ZK proofs are enabled for this peer.
	Supported bool `json:"supported"`

	// ProofSystem identifies the proof system (e.g., "plonk-bn254").
	// Peers must use the same proof system to exchange proofs.
	ProofSystem string `json:"proof_system"`

	// MaxSignatureBits is the maximum LSH signature length in bits.
	// Typically 256 bits. Peers must have matching signature lengths.
	MaxSignatureBits uint32 `json:"max_signature_bits"`
}

// NewZKCapability creates a ZKCapability advertising this node's capabilities.
// Use this to advertise our capabilities to other peers during discovery.
func NewZKCapability() *ZKCapability {
	return &ZKCapability{
		Supported:        true,
		ProofSystem:      SupportedProofSystem,
		MaxSignatureBits: SupportedSignatureBits,
	}
}

// CheckCompatibility verifies that a peer's ZK capability is compatible with ours.
//
// Returns nil if the peer is compatible, or an error describing the incompatibility.
// Errors may wrap ErrIncompatibleSystem for proof system mismatches.
func CheckCompatibility(peerCap *ZKCapability) error {
	if peerCap == nil {
		return fmt.Errorf("peer has no ZK capability")
	}

	if !peerCap.Supported {
		return fmt.Errorf("peer ZK not enabled")
	}

	if peerCap.ProofSystem != SupportedProofSystem {
		return fmt.Errorf("%w: peer uses %s, we use %s",
			ErrIncompatibleSystem,
			peerCap.ProofSystem,
			SupportedProofSystem,
		)
	}

	if peerCap.MaxSignatureBits != SupportedSignatureBits {
		return fmt.Errorf("signature length mismatch: peer=%d, local=%d",
			peerCap.MaxSignatureBits,
			SupportedSignatureBits,
		)
	}

	return nil
}

// ToProto converts this ZKCapability to its protobuf representation.
// Use this when sending capability advertisements over the network.
func (c *ZKCapability) ToProto() *pb.ZKCapability {
	return &pb.ZKCapability{
		Supported:        c.Supported,
		ProofSystem:      c.ProofSystem,
		MaxSignatureBits: c.MaxSignatureBits,
	}
}

// ZKCapabilityFromProto converts a protobuf ZKCapability to the internal type.
// Returns nil if the input is nil.
func ZKCapabilityFromProto(p *pb.ZKCapability) *ZKCapability {
	if p == nil {
		return nil
	}
	return &ZKCapability{
		Supported:        p.Supported,
		ProofSystem:      p.ProofSystem,
		MaxSignatureBits: p.MaxSignatureBits,
	}
}

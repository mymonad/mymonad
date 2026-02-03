// Package discovery provides peer discovery mechanisms for the P2P network.
// This file implements DHT bucket record types and signature lifecycle management
// for LSH-based peer discovery.
package discovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// DHT record lifecycle constants
const (
	// SignatureTTL is the validity period for DHT signature records.
	SignatureTTL = 1 * time.Hour

	// RepublishBuffer is the time before expiry to republish records.
	// Records are republished when their age exceeds (SignatureTTL - RepublishBuffer).
	RepublishBuffer = 5 * time.Minute

	// MinMonadDelta is the minimum change threshold for Monad regeneration.
	// If the Monad's affinity vector changes by less than this delta,
	// the signature is not regenerated.
	MinMonadDelta = 0.01
)

// Error definitions for DHT operations
var (
	// ErrNilRecord is returned when trying to serialize a nil BucketRecord.
	ErrNilRecord = errors.New("bucket record cannot be nil")

	// ErrEmptyData is returned when trying to deserialize empty data.
	ErrEmptyData = errors.New("data cannot be empty")

	// ErrInvalidPeerID is returned when peer ID cannot be decoded.
	ErrInvalidPeerID = errors.New("invalid peer ID")
)

// BucketRecord represents a peer's presence record in a DHT bucket.
// It contains the peer's network addresses for direct connection
// without revealing the LSH signature (privacy preservation).
type BucketRecord struct {
	// PeerID is the libp2p peer identifier.
	PeerID peer.ID `json:"-"` // Handled separately for proper serialization

	// Addresses are the multiaddrs where the peer can be reached.
	Addresses []string `json:"addrs"`

	// Timestamp is the Unix timestamp when this record was created.
	Timestamp int64 `json:"timestamp"`

	// TTL is the time-to-live in seconds until the record is considered stale.
	TTL int64 `json:"ttl"`

	// ZKCapability advertises the peer's ZK proof capabilities.
	// When nil, the peer does not support ZK proofs or hasn't advertised them.
	ZKCapability *ZKCapability `json:"zk_capability,omitempty"`
}

// ZKCapability represents a peer's zero-knowledge proof capability.
// This is used in DHT records to advertise ZK support during discovery.
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

// bucketRecordJSON is the JSON-serializable form of BucketRecord.
// It uses string for PeerID since peer.ID doesn't serialize well with json.Marshal.
type bucketRecordJSON struct {
	PeerID       string        `json:"peer_id"`
	Addresses    []string      `json:"addrs"`
	Timestamp    int64         `json:"timestamp"`
	TTL          int64         `json:"ttl"`
	ZKCapability *ZKCapability `json:"zk_capability,omitempty"`
}

// SignatureState tracks the lifecycle of an LSH signature for DHT publishing.
// It monitors when the signature was generated, what Monad state it was based on,
// and when it was last published to the DHT.
type SignatureState struct {
	// Signature is the LSH signature bytes.
	Signature []byte

	// GeneratedAt is when this signature was computed.
	GeneratedAt time.Time

	// PublishedAt is when this signature was last published to the DHT.
	PublishedAt time.Time

	// MonadHash is a hash of the Monad state when the signature was generated.
	// Used for change detection to determine if regeneration is needed.
	MonadHash []byte
}

// ShouldRegenerate returns true if the signature needs to be regenerated.
// This happens when:
//   - No signature exists (nil or empty)
//   - The Monad hash has changed (indicating the affinity vector changed)
//
// In production, this would compute the actual delta from the vector,
// but for now any hash change triggers regeneration.
func (s *SignatureState) ShouldRegenerate(currentMonadHash []byte) bool {
	// No signature - always regenerate
	if s.Signature == nil || len(s.Signature) == 0 {
		return true
	}

	// Compare Monad hashes - if different, signature may be stale
	// bytes.Equal handles nil comparison correctly (nil == nil is true)
	return !bytes.Equal(s.MonadHash, currentMonadHash)
}

// ShouldRepublish returns true if the DHT record needs to be refreshed.
// This is true when:
//   - Never published (zero PublishedAt)
//   - Time since publication exceeds (SignatureTTL - RepublishBuffer)
//
// This ensures records are refreshed before they expire in the DHT.
func (s *SignatureState) ShouldRepublish() bool {
	// Never published - definitely republish
	if s.PublishedAt.IsZero() {
		return true
	}

	// Check if we're within the republish buffer period
	// Republish when time since publication > (TTL - buffer)
	return time.Since(s.PublishedAt) > (SignatureTTL - RepublishBuffer)
}

// UpdateSignature updates the signature state with a new signature and Monad hash.
// The GeneratedAt timestamp is set to the current time.
func (s *SignatureState) UpdateSignature(sig []byte, monadHash []byte) {
	s.Signature = sig
	s.MonadHash = monadHash
	s.GeneratedAt = time.Now()
}

// MarkPublished records that the DHT record was published.
// Sets PublishedAt to the current time.
func (s *SignatureState) MarkPublished() {
	s.PublishedAt = time.Now()
}

// BucketRecordToJSON serializes a BucketRecord to JSON.
// The peer ID is converted to its string representation for JSON compatibility.
// Returns an error if the record is nil.
func BucketRecordToJSON(record *BucketRecord) ([]byte, error) {
	if record == nil {
		return nil, ErrNilRecord
	}

	// Convert to JSON-serializable form
	jsonRecord := bucketRecordJSON{
		PeerID:       record.PeerID.String(),
		Addresses:    record.Addresses,
		Timestamp:    record.Timestamp,
		TTL:          record.TTL,
		ZKCapability: record.ZKCapability,
	}

	return json.Marshal(jsonRecord)
}

// BucketRecordFromJSON deserializes a BucketRecord from JSON.
// The peer ID string is decoded back to a peer.ID.
// Returns an error if:
//   - The data is empty
//   - The JSON is malformed
//   - The peer ID cannot be decoded
func BucketRecordFromJSON(data []byte) (*BucketRecord, error) {
	if len(data) == 0 {
		return nil, ErrEmptyData
	}

	var jsonRecord bucketRecordJSON
	if err := json.Unmarshal(data, &jsonRecord); err != nil {
		return nil, err
	}

	// Decode peer ID from string
	peerID, err := peer.Decode(jsonRecord.PeerID)
	if err != nil {
		return nil, ErrInvalidPeerID
	}

	return &BucketRecord{
		PeerID:       peerID,
		Addresses:    jsonRecord.Addresses,
		Timestamp:    jsonRecord.Timestamp,
		TTL:          jsonRecord.TTL,
		ZKCapability: jsonRecord.ZKCapability,
	}, nil
}

// NewZKCapability creates a ZKCapability with the standard supported parameters.
// Use this when advertising ZK capability in DHT records.
func NewZKCapability() *ZKCapability {
	return &ZKCapability{
		Supported:        true,
		ProofSystem:      "plonk-bn254",
		MaxSignatureBits: 256,
	}
}

// IsCompatible checks if this ZK capability is compatible with another.
// Returns true if both peers can exchange ZK proofs.
func (z *ZKCapability) IsCompatible(other *ZKCapability) bool {
	if z == nil || other == nil {
		return false
	}
	if !z.Supported || !other.Supported {
		return false
	}
	if z.ProofSystem != other.ProofSystem {
		return false
	}
	if z.MaxSignatureBits != other.MaxSignatureBits {
		return false
	}
	return true
}

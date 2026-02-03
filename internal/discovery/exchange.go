// Package discovery provides peer discovery mechanisms for the P2P network.
// The Exchange struct captures immutable state at commit generation time.
// The SignatureSnapshot must be captured atomically to ensure mid-exchange
// Monad updates don't break commitment verification.
package discovery

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// ExchangeRole represents the role of a node in a signature exchange.
type ExchangeRole int

const (
	// RoleInitiator indicates the node that initiated the exchange.
	RoleInitiator ExchangeRole = iota
	// RoleResponder indicates the node that is responding to an exchange request.
	RoleResponder
)

// ExchangeState represents the current state of a signature exchange.
type ExchangeState int

const (
	// ExchangeStatePending indicates the exchange has been created but not started.
	ExchangeStatePending ExchangeState = iota
	// ExchangeStateCommitSent indicates our commitment has been sent to the peer.
	ExchangeStateCommitSent
	// ExchangeStateCommitReceived indicates we have received the peer's commitment.
	ExchangeStateCommitReceived
	// ExchangeStateRevealSent indicates we have sent our reveal (signature + salt).
	ExchangeStateRevealSent
	// ExchangeStateComplete indicates the exchange completed successfully.
	ExchangeStateComplete
	// ExchangeStateFailed indicates the exchange failed (e.g., verification error).
	ExchangeStateFailed
)

// ExchangeTimeout is the maximum duration for a signature exchange.
const ExchangeTimeout = 30 * time.Second

// Exchange captures immutable state at commit generation time.
// The SignatureSnapshot is copied at creation to ensure that mid-exchange
// Monad updates don't break commitment verification.
type Exchange struct {
	// PeerID identifies the remote peer in this exchange.
	PeerID peer.ID
	// Role indicates whether we initiated or are responding to this exchange.
	Role ExchangeRole
	// State tracks the current progress of the exchange.
	State ExchangeState

	// Snapshot: captured at commit generation, immutable for exchange lifetime.

	// SignatureSnapshot is our local LSH signature, copied at exchange creation.
	// This ensures that if the underlying Monad is updated during the exchange,
	// the commitment remains valid.
	SignatureSnapshot []byte
	// Salt is random bytes used to create the commitment (16+ bytes).
	Salt []byte
	// Commitment is SHA-256(SignatureSnapshot || Salt).
	Commitment []byte

	// Peer data (populated on receive).

	// PeerCommitment is the commitment received from the peer.
	PeerCommitment []byte
	// PeerSignature is the peer's revealed signature.
	PeerSignature []byte
	// PeerSalt is the peer's revealed salt.
	PeerSalt []byte

	// Timing.

	// CreatedAt is when this exchange was created.
	CreatedAt time.Time
	// ExpiresAt is when this exchange times out (CreatedAt + 30s).
	ExpiresAt time.Time
	// RetryCount tracks how many times we've retried this exchange.
	RetryCount int
}

// NewExchange creates a new exchange, snapshotting the current signature atomically.
// The signature is copied to ensure that modifications to the original slice
// don't affect the exchange's commitment validity.
func NewExchange(peerID peer.ID, role ExchangeRole, localSignature []byte) (*Exchange, error) {
	// Copy signature to snapshot (atomic capture).
	// This ensures modifications to localSignature after this call
	// don't affect the exchange.
	signatureSnapshot := make([]byte, len(localSignature))
	copy(signatureSnapshot, localSignature)

	// Generate random salt (16 bytes minimum).
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	// Compute commitment.
	commitment := computeCommitment(signatureSnapshot, salt)

	now := time.Now()
	return &Exchange{
		PeerID:            peerID,
		Role:              role,
		State:             ExchangeStatePending,
		SignatureSnapshot: signatureSnapshot,
		Salt:              salt,
		Commitment:        commitment,
		CreatedAt:         now,
		ExpiresAt:         now.Add(ExchangeTimeout),
	}, nil
}

// IsExpired returns true if the exchange has timed out.
func (e *Exchange) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// SetPeerCommitment stores the peer's commitment (received first in the protocol).
func (e *Exchange) SetPeerCommitment(commitment []byte) {
	e.PeerCommitment = commitment
}

// SetPeerReveal stores and verifies the peer's reveal (signature + salt).
// If verification fails, the exchange state is set to ExchangeStateFailed
// and an error is returned.
func (e *Exchange) SetPeerReveal(signature, salt []byte) error {
	if err := verifyCommitment(e.PeerCommitment, signature, salt); err != nil {
		e.State = ExchangeStateFailed
		return err
	}
	e.PeerSignature = signature
	e.PeerSalt = salt
	return nil
}

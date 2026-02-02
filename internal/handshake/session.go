// Package handshake provides session management for the handshake protocol.
package handshake

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	pb "github.com/mymonad/mymonad/api/proto"
	"github.com/mymonad/mymonad/pkg/protocol"
	"google.golang.org/protobuf/proto"
)

// ErrApprovalTimeout is returned when WaitForApproval times out.
var ErrApprovalTimeout = errors.New("approval timeout")

// DealBreakerConfig holds deal-breaker questions and their required answers.
type DealBreakerConfig struct {
	Questions []DealBreakerQuestion
}

// DealBreakerQuestion represents a single deal-breaker question.
type DealBreakerQuestion struct {
	ID       string // Unique identifier for the question
	Question string // The question text
	MyAnswer bool   // What I answer to this question
	Required bool   // If true, peer must also answer this way
}

// Session represents an active handshake with a peer.
type Session struct {
	mu sync.RWMutex

	ID           string
	PeerID       peer.ID
	Role         protocol.Role
	Handshake    *protocol.Handshake
	Stream       network.Stream
	StartedAt    time.Time
	LastActivity time.Time

	// Sensitive data - zeroed on cleanup
	LocalMonad []byte
	PeerMonad  []byte

	// Deal breaker configuration
	DealBreakerConfig *DealBreakerConfig

	// Approval state
	PendingApproval     bool
	PendingApprovalType string
	PendingAt           time.Time

	// Identity for unmask stage
	IdentityPayload *pb.IdentityPayload // Our identity to reveal
	PeerIdentity    *pb.IdentityPayload // Peer's revealed identity

	// Approval channel for async human approval
	approvalCh chan bool
}

// NewSession creates a new handshake session.
func NewSession(peerID peer.ID, role protocol.Role, threshold float32) *Session {
	now := time.Now()
	return &Session{
		ID:           uuid.New().String(),
		PeerID:       peerID,
		Role:         role,
		Handshake:    protocol.NewHandshake(role, peerID, threshold),
		StartedAt:    now,
		LastActivity: now,
		approvalCh:   make(chan bool, 1),
	}
}

// Cleanup zeroes sensitive data and releases resources.
// Must be called when session is complete or failed.
func (s *Session) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Zero sensitive byte slices
	for i := range s.LocalMonad {
		s.LocalMonad[i] = 0
	}
	s.LocalMonad = nil

	for i := range s.PeerMonad {
		s.PeerMonad[i] = 0
	}
	s.PeerMonad = nil

	// Zero identity payloads (security: zero-persistence constraint)
	if s.IdentityPayload != nil {
		// Zero the protobuf fields containing sensitive data
		s.IdentityPayload.DisplayName = ""
		s.IdentityPayload.Email = ""
		s.IdentityPayload.SignalNumber = ""
		s.IdentityPayload.MatrixId = ""
		s.IdentityPayload.PgpFingerprint = ""
		// Zero byte slices
		for i := range s.IdentityPayload.PgpPublicKey {
			s.IdentityPayload.PgpPublicKey[i] = 0
		}
		s.IdentityPayload.PgpPublicKey = nil
		for i := range s.IdentityPayload.ContactSignature {
			s.IdentityPayload.ContactSignature[i] = 0
		}
		s.IdentityPayload.ContactSignature = nil
		s.IdentityPayload = nil
	}

	if s.PeerIdentity != nil {
		// Zero the protobuf fields containing sensitive data
		s.PeerIdentity.DisplayName = ""
		s.PeerIdentity.Email = ""
		s.PeerIdentity.SignalNumber = ""
		s.PeerIdentity.MatrixId = ""
		s.PeerIdentity.PgpFingerprint = ""
		// Zero byte slices
		for i := range s.PeerIdentity.PgpPublicKey {
			s.PeerIdentity.PgpPublicKey[i] = 0
		}
		s.PeerIdentity.PgpPublicKey = nil
		for i := range s.PeerIdentity.ContactSignature {
			s.PeerIdentity.ContactSignature[i] = 0
		}
		s.PeerIdentity.ContactSignature = nil
		s.PeerIdentity = nil
	}

	// Close stream if open
	if s.Stream != nil {
		s.Stream.Close()
		s.Stream = nil
	}
}

// State returns the current handshake state.
func (s *Session) State() protocol.State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Handshake.State()
}

// ElapsedSeconds returns how long the session has been running.
func (s *Session) ElapsedSeconds() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(time.Since(s.StartedAt).Seconds())
}

// SetPendingApproval marks the session as waiting for human approval.
func (s *Session) SetPendingApproval(approvalType string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PendingApproval = true
	s.PendingApprovalType = approvalType
	s.PendingAt = time.Now()
}

// ClearPendingApproval clears the pending approval state.
func (s *Session) ClearPendingApproval() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PendingApproval = false
	s.PendingApprovalType = ""
}

// IsPendingApproval returns true if the session is waiting for human approval (thread-safe).
func (s *Session) IsPendingApproval() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.PendingApproval
}

// GetPendingApprovalType returns the type of pending approval (thread-safe).
func (s *Session) GetPendingApprovalType() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.PendingApprovalType
}

// UpdateActivity updates the last activity timestamp.
func (s *Session) UpdateActivity() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastActivity = time.Now()
}

// WaitForApproval blocks until human approval or rejection is signaled, or context is cancelled.
// Returns true if approved, false if rejected or context cancelled.
// Returns ErrApprovalTimeout if context is cancelled before approval is received.
func (s *Session) WaitForApproval(ctx context.Context) (bool, error) {
	select {
	case approved := <-s.approvalCh:
		return approved, nil
	case <-ctx.Done():
		return false, ErrApprovalTimeout
	}
}

// SignalApproval signals approval (true) or rejection (false) to unblock WaitForApproval.
// This is non-blocking; if the channel is full (signal already pending), the new signal
// is dropped and the method returns false. Callers should check the return value and log
// if needed. Returns true if signal was successfully sent.
func (s *Session) SignalApproval(approved bool) bool {
	select {
	case s.approvalCh <- approved:
		return true
	default:
		// Channel full, signal already pending
		return false
	}
}

// DrainApprovalChannel removes any pending approval signal from the channel.
// This should be called after timeout to prevent stale signals from affecting future waits.
func (s *Session) DrainApprovalChannel() {
	select {
	case <-s.approvalCh:
		// Discarded pending approval
	default:
		// Channel was empty
	}
}

// SetLocalMonad sets the local monad (thread-safe).
func (s *Session) SetLocalMonad(monad []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LocalMonad = monad
}

// GetLocalMonad returns a copy of the local monad (thread-safe).
func (s *Session) GetLocalMonad() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.LocalMonad == nil {
		return nil
	}
	result := make([]byte, len(s.LocalMonad))
	copy(result, s.LocalMonad)
	return result
}

// SetPeerMonad sets the peer monad (thread-safe).
func (s *Session) SetPeerMonad(monad []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PeerMonad = monad
}

// GetPeerMonad returns a copy of the peer monad (thread-safe).
func (s *Session) GetPeerMonad() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.PeerMonad == nil {
		return nil
	}
	result := make([]byte, len(s.PeerMonad))
	copy(result, s.PeerMonad)
	return result
}

// SetDealBreakerConfig sets the deal breaker configuration (thread-safe).
func (s *Session) SetDealBreakerConfig(cfg *DealBreakerConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DealBreakerConfig = cfg
}

// GetDealBreakerConfig returns a defensive copy of the deal breaker configuration (thread-safe).
// Callers may safely modify the returned value without affecting session state.
func (s *Session) GetDealBreakerConfig() *DealBreakerConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.DealBreakerConfig == nil {
		return nil
	}
	// Deep copy to prevent external mutation
	questions := make([]DealBreakerQuestion, len(s.DealBreakerConfig.Questions))
	copy(questions, s.DealBreakerConfig.Questions)
	return &DealBreakerConfig{Questions: questions}
}

// SetIdentityPayload sets the identity payload (thread-safe).
func (s *Session) SetIdentityPayload(payload *pb.IdentityPayload) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.IdentityPayload = payload
}

// GetIdentityPayload returns a defensive copy of the identity payload (thread-safe).
// Callers may safely modify the returned value without affecting session state.
func (s *Session) GetIdentityPayload() *pb.IdentityPayload {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.IdentityPayload == nil {
		return nil
	}
	return proto.Clone(s.IdentityPayload).(*pb.IdentityPayload)
}

// SetPeerIdentity sets the peer identity (thread-safe).
func (s *Session) SetPeerIdentity(payload *pb.IdentityPayload) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PeerIdentity = payload
}

// GetPeerIdentity returns a defensive copy of the peer identity (thread-safe).
// Callers may safely modify the returned value without affecting session state.
func (s *Session) GetPeerIdentity() *pb.IdentityPayload {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.PeerIdentity == nil {
		return nil
	}
	return proto.Clone(s.PeerIdentity).(*pb.IdentityPayload)
}

// SetStream sets the network stream (thread-safe).
func (s *Session) SetStream(stream network.Stream) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Stream = stream
}

// GetStream returns the network stream (thread-safe).
func (s *Session) GetStream() network.Stream {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Stream
}

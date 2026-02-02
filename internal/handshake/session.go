// Package handshake provides session management for the handshake protocol.
package handshake

import (
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	pb "github.com/mymonad/mymonad/api/proto"
	"github.com/mymonad/mymonad/pkg/protocol"
)

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

// UpdateActivity updates the last activity timestamp.
func (s *Session) UpdateActivity() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastActivity = time.Now()
}

// WaitForApproval blocks until human approval or rejection is signaled.
// Returns true if approved, false if rejected.
func (s *Session) WaitForApproval() bool {
	return <-s.approvalCh
}

// SignalApproval signals approval (true) or rejection (false) to unblock WaitForApproval.
// This is non-blocking; if the channel is full, the signal is dropped.
func (s *Session) SignalApproval(approved bool) {
	select {
	case s.approvalCh <- approved:
	default:
		// Channel full, signal already pending
	}
}

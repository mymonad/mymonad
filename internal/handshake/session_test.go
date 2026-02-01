// internal/handshake/session_test.go
package handshake

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mymonad/mymonad/pkg/protocol"
)

func TestNewSession(t *testing.T) {
	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	s := NewSession(peerID, protocol.RoleInitiator, 0.85)

	if s.ID == "" {
		t.Error("session ID should not be empty")
	}

	if s.PeerID != peerID {
		t.Error("peer ID mismatch")
	}

	if s.Role != protocol.RoleInitiator {
		t.Error("role mismatch")
	}

	if s.Handshake == nil {
		t.Error("handshake should not be nil")
	}

	if s.Handshake.State() != protocol.StateIdle {
		t.Errorf("expected StateIdle, got %s", s.Handshake.State())
	}
}

func TestSession_Cleanup(t *testing.T) {
	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	s := NewSession(peerID, protocol.RoleInitiator, 0.85)

	// Set some sensitive data
	s.LocalMonad = []byte{1, 2, 3, 4, 5}
	s.PeerMonad = []byte{6, 7, 8, 9, 10}

	s.Cleanup()

	// Verify data is zeroed
	if s.LocalMonad != nil {
		t.Error("LocalMonad should be nil after cleanup")
	}
	if s.PeerMonad != nil {
		t.Error("PeerMonad should be nil after cleanup")
	}
}

func TestSession_State(t *testing.T) {
	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	s := NewSession(peerID, protocol.RoleInitiator, 0.85)

	// Initial state should be Idle
	if s.State() != protocol.StateIdle {
		t.Errorf("expected StateIdle, got %s", s.State())
	}

	// Transition to attestation and verify
	err := s.Handshake.Transition(protocol.EventInitiate)
	if err != nil {
		t.Fatalf("transition failed: %v", err)
	}
	if s.State() != protocol.StateAttestation {
		t.Errorf("expected StateAttestation, got %s", s.State())
	}
}

func TestSession_ElapsedSeconds(t *testing.T) {
	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	s := NewSession(peerID, protocol.RoleInitiator, 0.85)

	// Elapsed time should be at least 0
	elapsed := s.ElapsedSeconds()
	if elapsed < 0 {
		t.Errorf("elapsed time should be non-negative, got %d", elapsed)
	}
}

func TestSession_PendingApproval(t *testing.T) {
	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	s := NewSession(peerID, protocol.RoleInitiator, 0.85)

	// Initially not pending
	if s.PendingApproval {
		t.Error("session should not be pending initially")
	}

	// Set pending
	s.SetPendingApproval("unmask")

	if !s.PendingApproval {
		t.Error("session should be pending after SetPendingApproval")
	}
	if s.PendingApprovalType != "unmask" {
		t.Errorf("expected approval type 'unmask', got '%s'", s.PendingApprovalType)
	}
	if s.PendingAt.IsZero() {
		t.Error("PendingAt should be set")
	}

	// Clear pending
	s.ClearPendingApproval()

	if s.PendingApproval {
		t.Error("session should not be pending after ClearPendingApproval")
	}
	if s.PendingApprovalType != "" {
		t.Errorf("approval type should be empty, got '%s'", s.PendingApprovalType)
	}
}

func TestSession_UpdateActivity(t *testing.T) {
	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	s := NewSession(peerID, protocol.RoleInitiator, 0.85)

	initialActivity := s.LastActivity

	// Small sleep to ensure time difference
	time.Sleep(10 * time.Millisecond)

	s.UpdateActivity()

	if !s.LastActivity.After(initialActivity) {
		t.Error("LastActivity should be updated to a later time")
	}
}

func TestSession_CleanupWithNilData(t *testing.T) {
	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	s := NewSession(peerID, protocol.RoleInitiator, 0.85)

	// LocalMonad and PeerMonad are nil by default
	// Cleanup should handle nil slices gracefully
	s.Cleanup()

	if s.LocalMonad != nil {
		t.Error("LocalMonad should be nil after cleanup")
	}
	if s.PeerMonad != nil {
		t.Error("PeerMonad should be nil after cleanup")
	}
}

func TestNewSession_ResponderRole(t *testing.T) {
	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	s := NewSession(peerID, protocol.RoleResponder, 0.75)

	if s.Role != protocol.RoleResponder {
		t.Error("role should be Responder")
	}

	if s.Handshake.Threshold() != 0.75 {
		t.Errorf("expected threshold 0.75, got %f", s.Handshake.Threshold())
	}
}

func TestNewSession_Timestamps(t *testing.T) {
	before := time.Now()
	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	s := NewSession(peerID, protocol.RoleInitiator, 0.85)
	after := time.Now()

	if s.StartedAt.Before(before) || s.StartedAt.After(after) {
		t.Error("StartedAt should be set to approximately now")
	}
	if s.LastActivity.Before(before) || s.LastActivity.After(after) {
		t.Error("LastActivity should be set to approximately now")
	}
}

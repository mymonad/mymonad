// internal/handshake/session_test.go
package handshake

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	pb "github.com/mymonad/mymonad/api/proto"
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

func TestSession_MonadAccessors(t *testing.T) {
	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	s := NewSession(peerID, protocol.RoleInitiator, 0.85)

	t.Run("LocalMonad nil initially", func(t *testing.T) {
		if s.GetLocalMonad() != nil {
			t.Error("LocalMonad should be nil initially")
		}
	})

	t.Run("SetLocalMonad and GetLocalMonad", func(t *testing.T) {
		monad := []byte{1, 2, 3, 4, 5}
		s.SetLocalMonad(monad)

		got := s.GetLocalMonad()
		if len(got) != len(monad) {
			t.Errorf("expected len %d, got %d", len(monad), len(got))
		}
		for i := range monad {
			if got[i] != monad[i] {
				t.Errorf("mismatch at index %d", i)
			}
		}
	})

	t.Run("GetLocalMonad returns copy", func(t *testing.T) {
		monad := []byte{1, 2, 3, 4, 5}
		s.SetLocalMonad(monad)

		got := s.GetLocalMonad()
		got[0] = 99 // Modify the returned copy

		// Original should be unchanged
		got2 := s.GetLocalMonad()
		if got2[0] != 1 {
			t.Error("GetLocalMonad should return a copy, not the original")
		}
	})

	t.Run("PeerMonad nil initially", func(t *testing.T) {
		if s.GetPeerMonad() != nil {
			t.Error("PeerMonad should be nil initially")
		}
	})

	t.Run("SetPeerMonad and GetPeerMonad", func(t *testing.T) {
		monad := []byte{6, 7, 8, 9, 10}
		s.SetPeerMonad(monad)

		got := s.GetPeerMonad()
		if len(got) != len(monad) {
			t.Errorf("expected len %d, got %d", len(monad), len(got))
		}
		for i := range monad {
			if got[i] != monad[i] {
				t.Errorf("mismatch at index %d", i)
			}
		}
	})

	t.Run("GetPeerMonad returns copy", func(t *testing.T) {
		monad := []byte{6, 7, 8, 9, 10}
		s.SetPeerMonad(monad)

		got := s.GetPeerMonad()
		got[0] = 99 // Modify the returned copy

		// Original should be unchanged
		got2 := s.GetPeerMonad()
		if got2[0] != 6 {
			t.Error("GetPeerMonad should return a copy, not the original")
		}
	})
}

func TestSession_DealBreakerConfigAccessors(t *testing.T) {
	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	s := NewSession(peerID, protocol.RoleInitiator, 0.85)

	t.Run("nil initially", func(t *testing.T) {
		if s.GetDealBreakerConfig() != nil {
			t.Error("DealBreakerConfig should be nil initially")
		}
	})

	t.Run("set and get", func(t *testing.T) {
		cfg := &DealBreakerConfig{
			Questions: []DealBreakerQuestion{
				{ID: "q1", Question: "Do you like cats?", MyAnswer: true, Required: true},
				{ID: "q2", Question: "Do you like dogs?", MyAnswer: false, Required: false},
			},
		}
		s.SetDealBreakerConfig(cfg)

		got := s.GetDealBreakerConfig()
		if got == nil {
			t.Fatal("GetDealBreakerConfig should not return nil after setting")
		}
		if len(got.Questions) != 2 {
			t.Errorf("expected 2 questions, got %d", len(got.Questions))
		}
		if got.Questions[0].ID != "q1" {
			t.Errorf("expected ID 'q1', got '%s'", got.Questions[0].ID)
		}
	})

	t.Run("returns defensive copy", func(t *testing.T) {
		cfg := &DealBreakerConfig{
			Questions: []DealBreakerQuestion{
				{ID: "q1", Question: "Original question", MyAnswer: true, Required: true},
			},
		}
		s.SetDealBreakerConfig(cfg)

		got := s.GetDealBreakerConfig()
		got.Questions[0].Question = "Modified question" // Modify the copy

		// Original should be unchanged
		got2 := s.GetDealBreakerConfig()
		if got2.Questions[0].Question != "Original question" {
			t.Error("GetDealBreakerConfig should return a defensive copy")
		}
	})
}

func TestSession_IdentityPayloadAccessors(t *testing.T) {
	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	t.Run("nil initially", func(t *testing.T) {
		s := NewSession(peerID, protocol.RoleInitiator, 0.85)
		if s.GetIdentityPayload() != nil {
			t.Error("IdentityPayload should be nil initially")
		}
		if s.GetPeerIdentity() != nil {
			t.Error("PeerIdentity should be nil initially")
		}
	})
}

func TestSession_PendingApprovalThreadSafe(t *testing.T) {
	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	s := NewSession(peerID, protocol.RoleInitiator, 0.85)

	t.Run("IsPendingApproval thread-safe accessor", func(t *testing.T) {
		if s.IsPendingApproval() {
			t.Error("should not be pending initially")
		}

		s.SetPendingApproval("unmask")
		if !s.IsPendingApproval() {
			t.Error("should be pending after SetPendingApproval")
		}

		s.ClearPendingApproval()
		if s.IsPendingApproval() {
			t.Error("should not be pending after ClearPendingApproval")
		}
	})

	t.Run("GetPendingApprovalType thread-safe accessor", func(t *testing.T) {
		if s.GetPendingApprovalType() != "" {
			t.Error("approval type should be empty initially")
		}

		s.SetPendingApproval("chat")
		if s.GetPendingApprovalType() != "chat" {
			t.Errorf("expected 'chat', got '%s'", s.GetPendingApprovalType())
		}
	})
}

func TestSession_DrainApprovalChannel(t *testing.T) {
	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	t.Run("drain when empty - no panic", func(t *testing.T) {
		s := NewSession(peerID, protocol.RoleInitiator, 0.85)
		// Should not panic when channel is empty
		s.DrainApprovalChannel()
	})

	t.Run("drain removes pending signal", func(t *testing.T) {
		s := NewSession(peerID, protocol.RoleInitiator, 0.85)

		// Send a signal
		if !s.SignalApproval(true) {
			t.Fatal("first signal should succeed")
		}

		// Drain it
		s.DrainApprovalChannel()

		// Now we should be able to send another signal
		if !s.SignalApproval(false) {
			t.Error("should be able to send signal after drain")
		}
	})
}

func TestSession_CleanupWithIdentityPayloads(t *testing.T) {
	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	s := NewSession(peerID, protocol.RoleInitiator, 0.85)

	// Set identity payloads (use direct field access since we're in same package)
	s.IdentityPayload = &pb.IdentityPayload{
		DisplayName:      "Test User",
		Email:            "test@example.com",
		SignalNumber:     "+1234567890",
		MatrixId:         "@test:matrix.org",
		PgpFingerprint:   "ABCD1234",
		PgpPublicKey:     []byte{1, 2, 3, 4, 5},
		ContactSignature: []byte{6, 7, 8, 9, 10},
	}
	s.PeerIdentity = &pb.IdentityPayload{
		DisplayName:      "Peer User",
		Email:            "peer@example.com",
		SignalNumber:     "+0987654321",
		MatrixId:         "@peer:matrix.org",
		PgpFingerprint:   "EFGH5678",
		PgpPublicKey:     []byte{11, 12, 13, 14, 15},
		ContactSignature: []byte{16, 17, 18, 19, 20},
	}

	s.Cleanup()

	if s.IdentityPayload != nil {
		t.Error("IdentityPayload should be nil after cleanup")
	}
	if s.PeerIdentity != nil {
		t.Error("PeerIdentity should be nil after cleanup")
	}
}

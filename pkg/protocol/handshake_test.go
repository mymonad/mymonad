package protocol

import (
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestNewHandshake(t *testing.T) {
	peerID := peer.ID("test-peer-id")
	threshold := float32(0.75)

	t.Run("creates initiator handshake", func(t *testing.T) {
		h := NewHandshake(RoleInitiator, peerID, threshold)

		if h == nil {
			t.Fatal("expected handshake, got nil")
		}
		if h.State() != StateIdle {
			t.Errorf("expected state Idle, got %v", h.State())
		}
		if h.Role() != RoleInitiator {
			t.Errorf("expected role Initiator, got %v", h.Role())
		}
		if h.PeerID() != peerID {
			t.Errorf("expected peerID %v, got %v", peerID, h.PeerID())
		}
		if h.Threshold() != threshold {
			t.Errorf("expected threshold %v, got %v", threshold, h.Threshold())
		}
		if h.StartTime().IsZero() {
			t.Error("expected non-zero start time")
		}
	})

	t.Run("creates responder handshake", func(t *testing.T) {
		h := NewHandshake(RoleResponder, peerID, threshold)

		if h.Role() != RoleResponder {
			t.Errorf("expected role Responder, got %v", h.Role())
		}
	})

	t.Run("validates threshold bounds", func(t *testing.T) {
		// Threshold should be clamped between 0 and 1
		hLow := NewHandshake(RoleInitiator, peerID, -0.5)
		if hLow.Threshold() < 0 {
			t.Errorf("threshold should be clamped to >= 0, got %v", hLow.Threshold())
		}

		hHigh := NewHandshake(RoleInitiator, peerID, 1.5)
		if hHigh.Threshold() > 1 {
			t.Errorf("threshold should be clamped to <= 1, got %v", hHigh.Threshold())
		}
	})
}

func TestHandshakeStateTransitions(t *testing.T) {
	peerID := peer.ID("test-peer-id")
	threshold := float32(0.75)

	t.Run("Idle to Attestation on initiate", func(t *testing.T) {
		h := NewHandshake(RoleInitiator, peerID, threshold)

		err := h.Transition(EventInitiate)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if h.State() != StateAttestation {
			t.Errorf("expected state Attestation, got %v", h.State())
		}
	})

	t.Run("Attestation to VectorMatch on success", func(t *testing.T) {
		h := NewHandshake(RoleInitiator, peerID, threshold)
		_ = h.Transition(EventInitiate)

		err := h.Transition(EventAttestationSuccess)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if h.State() != StateVectorMatch {
			t.Errorf("expected state VectorMatch, got %v", h.State())
		}
	})

	t.Run("Attestation to Failed on failure", func(t *testing.T) {
		h := NewHandshake(RoleInitiator, peerID, threshold)
		_ = h.Transition(EventInitiate)

		err := h.Transition(EventAttestationFailure)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if h.State() != StateFailed {
			t.Errorf("expected state Failed, got %v", h.State())
		}
		if !h.IsFailed() {
			t.Error("expected IsFailed() to return true")
		}
	})

	t.Run("VectorMatch to DealBreakers on match above threshold", func(t *testing.T) {
		h := NewHandshake(RoleInitiator, peerID, threshold)
		_ = h.Transition(EventInitiate)
		_ = h.Transition(EventAttestationSuccess)

		err := h.Transition(EventMatchAboveThreshold)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if h.State() != StateDealBreakers {
			t.Errorf("expected state DealBreakers, got %v", h.State())
		}
	})

	t.Run("VectorMatch to Failed on match below threshold", func(t *testing.T) {
		h := NewHandshake(RoleInitiator, peerID, threshold)
		_ = h.Transition(EventInitiate)
		_ = h.Transition(EventAttestationSuccess)

		err := h.Transition(EventMatchBelowThreshold)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if h.State() != StateFailed {
			t.Errorf("expected state Failed, got %v", h.State())
		}
	})

	t.Run("DealBreakers to HumanChat on all match", func(t *testing.T) {
		h := NewHandshake(RoleInitiator, peerID, threshold)
		_ = h.Transition(EventInitiate)
		_ = h.Transition(EventAttestationSuccess)
		_ = h.Transition(EventMatchAboveThreshold)

		err := h.Transition(EventDealBreakersMatch)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if h.State() != StateHumanChat {
			t.Errorf("expected state HumanChat, got %v", h.State())
		}
	})

	t.Run("DealBreakers to Failed on mismatch", func(t *testing.T) {
		h := NewHandshake(RoleInitiator, peerID, threshold)
		_ = h.Transition(EventInitiate)
		_ = h.Transition(EventAttestationSuccess)
		_ = h.Transition(EventMatchAboveThreshold)

		err := h.Transition(EventDealBreakersMismatch)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if h.State() != StateFailed {
			t.Errorf("expected state Failed, got %v", h.State())
		}
	})

	t.Run("HumanChat to Unmask on approval", func(t *testing.T) {
		h := NewHandshake(RoleInitiator, peerID, threshold)
		_ = h.Transition(EventInitiate)
		_ = h.Transition(EventAttestationSuccess)
		_ = h.Transition(EventMatchAboveThreshold)
		_ = h.Transition(EventDealBreakersMatch)

		err := h.Transition(EventChatApproval)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if h.State() != StateUnmask {
			t.Errorf("expected state Unmask, got %v", h.State())
		}
	})

	t.Run("HumanChat to Failed on rejection", func(t *testing.T) {
		h := NewHandshake(RoleInitiator, peerID, threshold)
		_ = h.Transition(EventInitiate)
		_ = h.Transition(EventAttestationSuccess)
		_ = h.Transition(EventMatchAboveThreshold)
		_ = h.Transition(EventDealBreakersMatch)

		err := h.Transition(EventChatRejection)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if h.State() != StateFailed {
			t.Errorf("expected state Failed, got %v", h.State())
		}
	})

	t.Run("HumanChat to Failed on timeout", func(t *testing.T) {
		h := NewHandshake(RoleInitiator, peerID, threshold)
		_ = h.Transition(EventInitiate)
		_ = h.Transition(EventAttestationSuccess)
		_ = h.Transition(EventMatchAboveThreshold)
		_ = h.Transition(EventDealBreakersMatch)

		err := h.Transition(EventTimeout)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if h.State() != StateFailed {
			t.Errorf("expected state Failed, got %v", h.State())
		}
	})

	t.Run("Unmask to Complete on mutual approval", func(t *testing.T) {
		h := NewHandshake(RoleInitiator, peerID, threshold)
		_ = h.Transition(EventInitiate)
		_ = h.Transition(EventAttestationSuccess)
		_ = h.Transition(EventMatchAboveThreshold)
		_ = h.Transition(EventDealBreakersMatch)
		_ = h.Transition(EventChatApproval)

		err := h.Transition(EventMutualApproval)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if h.State() != StateComplete {
			t.Errorf("expected state Complete, got %v", h.State())
		}
		if !h.IsComplete() {
			t.Error("expected IsComplete() to return true")
		}
	})

	t.Run("Unmask to Failed on rejection", func(t *testing.T) {
		h := NewHandshake(RoleInitiator, peerID, threshold)
		_ = h.Transition(EventInitiate)
		_ = h.Transition(EventAttestationSuccess)
		_ = h.Transition(EventMatchAboveThreshold)
		_ = h.Transition(EventDealBreakersMatch)
		_ = h.Transition(EventChatApproval)

		err := h.Transition(EventUnmaskRejection)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if h.State() != StateFailed {
			t.Errorf("expected state Failed, got %v", h.State())
		}
	})
}

func TestInvalidTransitions(t *testing.T) {
	peerID := peer.ID("test-peer-id")
	threshold := float32(0.75)

	t.Run("cannot transition from Idle with wrong event", func(t *testing.T) {
		h := NewHandshake(RoleInitiator, peerID, threshold)

		err := h.Transition(EventAttestationSuccess)
		if err == nil {
			t.Error("expected error for invalid transition")
		}
		if h.State() != StateIdle {
			t.Errorf("state should remain Idle, got %v", h.State())
		}
	})

	t.Run("cannot transition from Complete state", func(t *testing.T) {
		h := NewHandshake(RoleInitiator, peerID, threshold)
		_ = h.Transition(EventInitiate)
		_ = h.Transition(EventAttestationSuccess)
		_ = h.Transition(EventMatchAboveThreshold)
		_ = h.Transition(EventDealBreakersMatch)
		_ = h.Transition(EventChatApproval)
		_ = h.Transition(EventMutualApproval)

		err := h.Transition(EventInitiate)
		if err == nil {
			t.Error("expected error when transitioning from Complete")
		}
	})

	t.Run("cannot transition from Failed state", func(t *testing.T) {
		h := NewHandshake(RoleInitiator, peerID, threshold)
		_ = h.Transition(EventInitiate)
		_ = h.Transition(EventAttestationFailure)

		err := h.Transition(EventInitiate)
		if err == nil {
			t.Error("expected error when transitioning from Failed")
		}
	})

	t.Run("Attestation rejects VectorMatch events", func(t *testing.T) {
		h := NewHandshake(RoleInitiator, peerID, threshold)
		_ = h.Transition(EventInitiate)

		err := h.Transition(EventMatchAboveThreshold)
		if err == nil {
			t.Error("expected error for invalid event in Attestation state")
		}
	})

	t.Run("VectorMatch rejects DealBreaker events", func(t *testing.T) {
		h := NewHandshake(RoleInitiator, peerID, threshold)
		_ = h.Transition(EventInitiate)
		_ = h.Transition(EventAttestationSuccess)

		err := h.Transition(EventDealBreakersMatch)
		if err == nil {
			t.Error("expected error for invalid event in VectorMatch state")
		}
	})
}

func TestHandshakeThreadSafety(t *testing.T) {
	peerID := peer.ID("test-peer-id")
	threshold := float32(0.75)

	t.Run("concurrent state reads are safe", func(t *testing.T) {
		h := NewHandshake(RoleInitiator, peerID, threshold)
		_ = h.Transition(EventInitiate)

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = h.State()
				_ = h.IsComplete()
				_ = h.IsFailed()
				_ = h.Role()
				_ = h.PeerID()
				_ = h.Threshold()
				_ = h.StartTime()
			}()
		}
		wg.Wait()
	})

	t.Run("concurrent transitions are serialized", func(t *testing.T) {
		// Multiple goroutines trying to transition, only one should succeed
		h := NewHandshake(RoleInitiator, peerID, threshold)

		var wg sync.WaitGroup
		successCount := 0
		var mu sync.Mutex

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := h.Transition(EventInitiate)
				if err == nil {
					mu.Lock()
					successCount++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()

		if successCount != 1 {
			t.Errorf("expected exactly 1 successful transition, got %d", successCount)
		}
	})
}

func TestStateString(t *testing.T) {
	tests := []struct {
		state    State
		expected string
	}{
		{StateIdle, "Idle"},
		{StateAttestation, "Attestation"},
		{StateVectorMatch, "VectorMatch"},
		{StateDealBreakers, "DealBreakers"},
		{StateHumanChat, "HumanChat"},
		{StateUnmask, "Unmask"},
		{StateComplete, "Complete"},
		{StateFailed, "Failed"},
		{State(99), "Unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.state.String(); got != tt.expected {
				t.Errorf("State.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEventString(t *testing.T) {
	tests := []struct {
		event    Event
		expected string
	}{
		{EventInitiate, "Initiate"},
		{EventAttestationSuccess, "AttestationSuccess"},
		{EventAttestationFailure, "AttestationFailure"},
		{EventMatchAboveThreshold, "MatchAboveThreshold"},
		{EventMatchBelowThreshold, "MatchBelowThreshold"},
		{EventDealBreakersMatch, "DealBreakersMatch"},
		{EventDealBreakersMismatch, "DealBreakersMismatch"},
		{EventChatApproval, "ChatApproval"},
		{EventChatRejection, "ChatRejection"},
		{EventTimeout, "Timeout"},
		{EventMutualApproval, "MutualApproval"},
		{EventUnmaskRejection, "UnmaskRejection"},
		{Event(99), "Unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.event.String(); got != tt.expected {
				t.Errorf("Event.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRoleString(t *testing.T) {
	tests := []struct {
		role     Role
		expected string
	}{
		{RoleInitiator, "Initiator"},
		{RoleResponder, "Responder"},
		{Role(99), "Unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.role.String(); got != tt.expected {
				t.Errorf("Role.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHandshakeCompletePath(t *testing.T) {
	peerID := peer.ID("test-peer-id")
	threshold := float32(0.75)

	h := NewHandshake(RoleInitiator, peerID, threshold)

	// Full successful handshake path
	transitions := []Event{
		EventInitiate,
		EventAttestationSuccess,
		EventMatchAboveThreshold,
		EventDealBreakersMatch,
		EventChatApproval,
		EventMutualApproval,
	}

	expectedStates := []State{
		StateAttestation,
		StateVectorMatch,
		StateDealBreakers,
		StateHumanChat,
		StateUnmask,
		StateComplete,
	}

	for i, event := range transitions {
		err := h.Transition(event)
		if err != nil {
			t.Fatalf("transition %d (%v) failed: %v", i, event, err)
		}
		if h.State() != expectedStates[i] {
			t.Errorf("after transition %d, expected state %v, got %v",
				i, expectedStates[i], h.State())
		}
	}

	if !h.IsComplete() {
		t.Error("handshake should be complete")
	}
	if h.IsFailed() {
		t.Error("handshake should not be failed")
	}
}

func TestHandshakeDuration(t *testing.T) {
	peerID := peer.ID("test-peer-id")
	threshold := float32(0.75)

	h := NewHandshake(RoleInitiator, peerID, threshold)
	startTime := h.StartTime()

	// Small delay to ensure time has passed
	time.Sleep(10 * time.Millisecond)

	duration := h.Duration()
	if duration < 10*time.Millisecond {
		t.Errorf("expected duration >= 10ms, got %v", duration)
	}

	if h.StartTime() != startTime {
		t.Error("start time should not change")
	}
}

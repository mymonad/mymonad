// internal/handshake/manager_test.go
package handshake

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mymonad/mymonad/pkg/protocol"
)

func TestNewManager(t *testing.T) {
	cfg := ManagerConfig{
		AutoInitiate:     true,
		CooldownDuration: 1 * time.Hour,
		Threshold:        0.85,
	}

	m := NewManager(nil, cfg) // nil host for unit test

	if m == nil {
		t.Fatal("manager should not be nil")
	}

	if !m.cfg.AutoInitiate {
		t.Error("auto initiate should be true")
	}
}

func TestManager_CanInitiate(t *testing.T) {
	cfg := ManagerConfig{
		CooldownDuration: 1 * time.Hour,
		Threshold:        0.85,
	}
	m := NewManager(nil, cfg)

	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Should be able to initiate to new peer
	if !m.CanInitiate(peerID) {
		t.Error("should be able to initiate to new peer")
	}

	// Record an attempt
	m.RecordAttempt(peerID)

	// Should not be able to initiate again (cooldown)
	if m.CanInitiate(peerID) {
		t.Error("should not be able to initiate during cooldown")
	}
}

func TestManager_AddRemoveSession(t *testing.T) {
	cfg := ManagerConfig{
		CooldownDuration: 1 * time.Hour,
		Threshold:        0.85,
	}
	m := NewManager(nil, cfg)

	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Add session
	s := m.CreateSession(peerID, protocol.RoleInitiator)
	if s == nil {
		t.Fatal("session should not be nil")
	}

	// Should find session
	found := m.GetSession(s.ID)
	if found == nil {
		t.Error("should find session by ID")
	}

	// Remove session
	m.RemoveSession(s.ID)

	// Should not find session
	found = m.GetSession(s.ID)
	if found != nil {
		t.Error("should not find removed session")
	}

	// PeerHistory should be updated
	if m.CanInitiate(peerID) {
		t.Error("should not be able to initiate after session removal (cooldown)")
	}
}

func TestManager_GetSessionByPeer(t *testing.T) {
	cfg := ManagerConfig{
		CooldownDuration: 1 * time.Hour,
		Threshold:        0.85,
	}
	m := NewManager(nil, cfg)

	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	peerID2, _ := peer.Decode("12D3KooWBmAwcd4PJNJvfV89HwE48nwkRmAgo8Vy3uQEyNNHBox2")

	// No session exists
	s := m.GetSessionByPeer(peerID)
	if s != nil {
		t.Error("should not find session for unknown peer")
	}

	// Create a session
	created := m.CreateSession(peerID, protocol.RoleInitiator)

	// Should find session by peer
	found := m.GetSessionByPeer(peerID)
	if found == nil {
		t.Error("should find session by peer ID")
	}
	if found.ID != created.ID {
		t.Error("found session should match created session")
	}

	// Should not find session for different peer
	found = m.GetSessionByPeer(peerID2)
	if found != nil {
		t.Error("should not find session for different peer")
	}
}

func TestManager_CanInitiate_ActiveSession(t *testing.T) {
	cfg := ManagerConfig{
		CooldownDuration: 1 * time.Millisecond, // very short cooldown
		Threshold:        0.85,
	}
	m := NewManager(nil, cfg)

	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Create an active session
	s := m.CreateSession(peerID, protocol.RoleInitiator)

	// Wait for cooldown to expire
	time.Sleep(5 * time.Millisecond)

	// Should NOT be able to initiate because there's an active (non-terminal) session
	if m.CanInitiate(peerID) {
		t.Error("should not be able to initiate when active session exists")
	}

	// Transition session to terminal state
	_ = s.Handshake.Transition(protocol.EventInitiate) // Idle -> Attestation
	_ = s.Handshake.Transition(protocol.EventAttestationFailure) // -> Failed (terminal)

	// Wait for cooldown again
	time.Sleep(5 * time.Millisecond)

	// NOW should be able to initiate (session is terminal, cooldown expired)
	if !m.CanInitiate(peerID) {
		t.Error("should be able to initiate after session is terminal and cooldown expired")
	}
}

func TestManager_ListSessions(t *testing.T) {
	cfg := ManagerConfig{
		CooldownDuration: 1 * time.Hour,
		Threshold:        0.85,
	}
	m := NewManager(nil, cfg)

	// Initially empty
	sessions := m.ListSessions()
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}

	peerID1, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	peerID2, _ := peer.Decode("12D3KooWBmAwcd4PJNJvfV89HwE48nwkRmAgo8Vy3uQEyNNHBox2")

	// Create two sessions
	s1 := m.CreateSession(peerID1, protocol.RoleInitiator)
	s2 := m.CreateSession(peerID2, protocol.RoleResponder)

	sessions = m.ListSessions()
	if len(sessions) != 2 {
		t.Errorf("expected 2 sessions, got %d", len(sessions))
	}

	// Verify both sessions are in the list
	foundS1, foundS2 := false, false
	for _, s := range sessions {
		if s.ID == s1.ID {
			foundS1 = true
		}
		if s.ID == s2.ID {
			foundS2 = true
		}
	}
	if !foundS1 {
		t.Error("session 1 not found in list")
	}
	if !foundS2 {
		t.Error("session 2 not found in list")
	}
}

func TestManager_SubscribeAndEmitEvent(t *testing.T) {
	cfg := ManagerConfig{
		CooldownDuration: 1 * time.Hour,
		Threshold:        0.85,
	}
	m := NewManager(nil, cfg)

	// Subscribe
	ch := m.Subscribe()

	// Emit event
	event := Event{
		SessionID:      "test-session-id",
		EventType:      "StateChange",
		State:          "VectorMatch",
		PeerID:         "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
		ElapsedSeconds: 10,
	}
	m.EmitEvent(event)

	// Receive event
	select {
	case received := <-ch:
		if received.SessionID != event.SessionID {
			t.Errorf("expected session ID %s, got %s", event.SessionID, received.SessionID)
		}
		if received.EventType != event.EventType {
			t.Errorf("expected event type %s, got %s", event.EventType, received.EventType)
		}
		if received.State != event.State {
			t.Errorf("expected state %s, got %s", event.State, received.State)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for event")
	}
}

func TestManager_EmitEvent_FullChannel(t *testing.T) {
	cfg := ManagerConfig{
		CooldownDuration: 1 * time.Hour,
		Threshold:        0.85,
	}
	m := NewManager(nil, cfg)

	// Subscribe
	ch := m.Subscribe()

	// Fill the channel (capacity is 100)
	for i := 0; i < 100; i++ {
		m.EmitEvent(Event{SessionID: "fill"})
	}

	// Emit one more - should not block (gets dropped)
	done := make(chan bool)
	go func() {
		m.EmitEvent(Event{SessionID: "overflow"})
		done <- true
	}()

	select {
	case <-done:
		// Good, didn't block
	case <-time.After(100 * time.Millisecond):
		t.Error("EmitEvent blocked on full channel")
	}

	// Drain the channel
	count := 0
	for len(ch) > 0 {
		<-ch
		count++
	}
	if count != 100 {
		t.Errorf("expected 100 events in channel, got %d", count)
	}
}

func TestManager_CleanupStaleSessions(t *testing.T) {
	cfg := ManagerConfig{
		CooldownDuration: 1 * time.Millisecond,
		Threshold:        0.85,
	}
	m := NewManager(nil, cfg)

	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Create a session and transition to terminal state
	s := m.CreateSession(peerID, protocol.RoleInitiator)
	_ = s.Handshake.Transition(protocol.EventInitiate)
	_ = s.Handshake.Transition(protocol.EventAttestationFailure) // -> Failed

	// Set LastActivity to be old
	s.LastActivity = time.Now().Add(-2 * time.Hour)

	// Session should exist
	if m.GetSession(s.ID) == nil {
		t.Fatal("session should exist before cleanup")
	}

	// Run cleanup with staleAfter = 1 hour
	m.cleanupStaleSessions(1 * time.Hour)

	// Session should be removed (terminal + stale)
	if m.GetSession(s.ID) != nil {
		t.Error("stale terminal session should be removed")
	}
}

func TestManager_CleanupStaleSessions_KeepsActive(t *testing.T) {
	cfg := ManagerConfig{
		CooldownDuration: 1 * time.Hour,
		Threshold:        0.85,
	}
	m := NewManager(nil, cfg)

	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Create a session but don't transition to terminal
	s := m.CreateSession(peerID, protocol.RoleInitiator)
	_ = s.Handshake.Transition(protocol.EventInitiate) // Idle -> Attestation (not terminal)

	// Set LastActivity to be old
	s.LastActivity = time.Now().Add(-2 * time.Hour)

	// Run cleanup
	m.cleanupStaleSessions(1 * time.Hour)

	// Session should still exist (not terminal)
	if m.GetSession(s.ID) == nil {
		t.Error("non-terminal session should not be removed")
	}
}

func TestManager_CleanupStaleSessions_KeepsRecent(t *testing.T) {
	cfg := ManagerConfig{
		CooldownDuration: 1 * time.Hour,
		Threshold:        0.85,
	}
	m := NewManager(nil, cfg)

	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Create a terminal session with recent activity
	s := m.CreateSession(peerID, protocol.RoleInitiator)
	_ = s.Handshake.Transition(protocol.EventInitiate)
	_ = s.Handshake.Transition(protocol.EventAttestationFailure)
	s.LastActivity = time.Now() // Recent

	// Run cleanup
	m.cleanupStaleSessions(1 * time.Hour)

	// Session should still exist (not stale)
	if m.GetSession(s.ID) == nil {
		t.Error("recent terminal session should not be removed")
	}
}

func TestManager_CleanupLoop(t *testing.T) {
	cfg := ManagerConfig{
		CooldownDuration: 1 * time.Millisecond,
		Threshold:        0.85,
	}
	m := NewManager(nil, cfg)

	ctx, cancel := context.WithCancel(context.Background())

	// Start cleanup loop
	done := make(chan bool)
	go func() {
		m.CleanupLoop(ctx, 1*time.Hour)
		done <- true
	}()

	// Cancel context
	cancel()

	// Loop should exit
	select {
	case <-done:
		// Good
	case <-time.After(500 * time.Millisecond):
		t.Error("CleanupLoop didn't exit after context cancel")
	}
}

func TestManager_RemoveSession_NonExistent(t *testing.T) {
	cfg := ManagerConfig{
		CooldownDuration: 1 * time.Hour,
		Threshold:        0.85,
	}
	m := NewManager(nil, cfg)

	// Should not panic when removing non-existent session
	m.RemoveSession("non-existent-id")
}

func TestManager_MultipleSubscribers(t *testing.T) {
	cfg := ManagerConfig{
		CooldownDuration: 1 * time.Hour,
		Threshold:        0.85,
	}
	m := NewManager(nil, cfg)

	// Create multiple subscribers
	ch1 := m.Subscribe()
	ch2 := m.Subscribe()
	ch3 := m.Subscribe()

	// Emit event
	event := Event{SessionID: "multi-test"}
	m.EmitEvent(event)

	// All subscribers should receive the event
	for i, ch := range []<-chan Event{ch1, ch2, ch3} {
		select {
		case received := <-ch:
			if received.SessionID != event.SessionID {
				t.Errorf("subscriber %d: expected session ID %s, got %s", i, event.SessionID, received.SessionID)
			}
		case <-time.After(100 * time.Millisecond):
			t.Errorf("subscriber %d: timeout waiting for event", i)
		}
	}
}

func TestManager_ListSessionsInfo(t *testing.T) {
	cfg := ManagerConfig{
		CooldownDuration: 1 * time.Hour,
		Threshold:        0.85,
	}
	m := NewManager(nil, cfg)

	t.Run("empty initially", func(t *testing.T) {
		infos := m.ListSessionsInfo()
		if len(infos) != 0 {
			t.Errorf("expected 0 sessions, got %d", len(infos))
		}
	})

	t.Run("returns session info", func(t *testing.T) {
		peerID1, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
		peerID2, _ := peer.Decode("12D3KooWBmAwcd4PJNJvfV89HwE48nwkRmAgo8Vy3uQEyNNHBox2")

		s1 := m.CreateSession(peerID1, protocol.RoleInitiator)
		_ = m.CreateSession(peerID2, protocol.RoleResponder)

		// Set pending approval on one session
		s1.SetPendingApproval("unmask")

		infos := m.ListSessionsInfo()
		if len(infos) != 2 {
			t.Errorf("expected 2 sessions, got %d", len(infos))
		}

		// Find s1 info
		var s1Info *SessionInfo
		for i := range infos {
			if infos[i].ID == s1.ID {
				s1Info = &infos[i]
				break
			}
		}

		if s1Info == nil {
			t.Fatal("session 1 not found in ListSessionsInfo")
		}

		if s1Info.PeerID != peerID1.String() {
			t.Errorf("expected peer ID %s, got %s", peerID1.String(), s1Info.PeerID)
		}
		if s1Info.Role != "Initiator" {
			t.Errorf("expected role Initiator, got %s", s1Info.Role)
		}
		if s1Info.State != "Idle" {
			t.Errorf("expected state Idle, got %s", s1Info.State)
		}
		if !s1Info.PendingApproval {
			t.Error("expected PendingApproval to be true")
		}
		if s1Info.ApprovalType != "unmask" {
			t.Errorf("expected approval type 'unmask', got '%s'", s1Info.ApprovalType)
		}
	})

	t.Run("info is a snapshot not live reference", func(t *testing.T) {
		peerID, _ := peer.Decode("12D3KooWNvSZnPi3RrPNb9vuPpE24Hq3njz7AHvJtvJsLanPgiKS")
		s := m.CreateSession(peerID, protocol.RoleInitiator)

		infos := m.ListSessionsInfo()
		var info *SessionInfo
		for i := range infos {
			if infos[i].ID == s.ID {
				info = &infos[i]
				break
			}
		}

		if info == nil {
			t.Fatal("session not found")
		}

		// The original state
		if info.State != "Idle" {
			t.Errorf("expected state Idle, got %s", info.State)
		}

		// Transition the session
		_ = s.Handshake.Transition(protocol.EventInitiate)

		// The info should still show the old state (it's a snapshot)
		// Note: This is expected behavior - ListSessionsInfo returns a snapshot
		// The live session state has changed, but our info copy hasn't
		if info.State != "Idle" {
			t.Error("SessionInfo should be a snapshot, not a live reference")
		}
	})
}

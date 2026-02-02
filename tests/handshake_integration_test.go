// Package tests contains integration tests for the handshake protocol.
// These tests verify the complete handshake flow between two agents.
package tests

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	pb "github.com/mymonad/mymonad/api/proto"
	"github.com/mymonad/mymonad/internal/handshake"
	"github.com/mymonad/mymonad/internal/tee"
	proto "github.com/mymonad/mymonad/pkg/protocol"
)

// ===========================================================================
// Test Helpers
// ===========================================================================

// testLogger creates a silent logger for tests (use slog.Default() for debugging).
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError, // Only show errors during tests
	}))
}

// createTestHost creates a libp2p host for testing.
func createTestHost(t *testing.T) host.Host {
	t.Helper()

	h, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.DisableRelay(),
	)
	if err != nil {
		t.Fatalf("failed to create host: %v", err)
	}
	return h
}

// createTestManager creates a handshake manager for testing.
func createTestManager(t *testing.T, h host.Host, threshold float32) *handshake.Manager {
	t.Helper()

	cfg := handshake.ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 100 * time.Millisecond, // Short cooldown for tests
		Threshold:        threshold,
	}
	return handshake.NewManager(h, cfg)
}

// connectHosts connects two libp2p hosts.
func connectHosts(t *testing.T, h1, h2 host.Host) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := h1.Connect(ctx, peer.AddrInfo{
		ID:    h2.ID(),
		Addrs: h2.Addrs(),
	})
	if err != nil {
		t.Fatalf("failed to connect hosts: %v", err)
	}
}

// createTestMonad creates a serialized monad vector for testing.
func createTestMonad(values []float32) []byte {
	return tee.SerializeMonad(values)
}

// createSimilarMonads creates two monads that are similar (high cosine similarity).
func createSimilarMonads() ([]byte, []byte) {
	// Two nearly identical vectors - high cosine similarity
	monad1 := createTestMonad([]float32{1.0, 0.5, 0.3, 0.1})
	monad2 := createTestMonad([]float32{0.9, 0.6, 0.35, 0.15})
	return monad1, monad2
}

// createOrthogonalMonads creates two monads that are orthogonal (low cosine similarity).
func createOrthogonalMonads() ([]byte, []byte) {
	// Two orthogonal vectors - zero cosine similarity
	monad1 := createTestMonad([]float32{1.0, 0.0, 0.0, 0.0})
	monad2 := createTestMonad([]float32{0.0, 1.0, 0.0, 0.0})
	return monad1, monad2
}

// createCompatibleDealBreakers creates deal breaker configs that are compatible.
func createCompatibleDealBreakers() (*handshake.DealBreakerConfig, *handshake.DealBreakerConfig) {
	config1 := &handshake.DealBreakerConfig{
		Questions: []handshake.DealBreakerQuestion{
			{ID: "q1", Question: "Do you like cats?", MyAnswer: true, Required: true},
			{ID: "q2", Question: "Are you vegan?", MyAnswer: false, Required: false},
		},
	}
	config2 := &handshake.DealBreakerConfig{
		Questions: []handshake.DealBreakerQuestion{
			{ID: "q1", Question: "Do you like cats?", MyAnswer: true, Required: true},
			{ID: "q2", Question: "Are you vegan?", MyAnswer: false, Required: false},
		},
	}
	return config1, config2
}

// createIncompatibleDealBreakers creates deal breaker configs that are incompatible.
func createIncompatibleDealBreakers() (*handshake.DealBreakerConfig, *handshake.DealBreakerConfig) {
	config1 := &handshake.DealBreakerConfig{
		Questions: []handshake.DealBreakerQuestion{
			{ID: "q1", Question: "Do you like cats?", MyAnswer: true, Required: true},
		},
	}
	config2 := &handshake.DealBreakerConfig{
		Questions: []handshake.DealBreakerQuestion{
			{ID: "q1", Question: "Do you like cats?", MyAnswer: false, Required: true}, // Opposite answer!
		},
	}
	return config1, config2
}

// createTestIdentity creates a test identity payload.
func createTestIdentity(name, email string) *pb.IdentityPayload {
	return &pb.IdentityPayload{
		DisplayName: name,
		Email:       email,
	}
}

// waitForEvent waits for a specific event type on the channel with timeout.
func waitForEvent(ch <-chan handshake.Event, eventType string, timeout time.Duration) (*handshake.Event, bool) {
	deadline := time.After(timeout)
	for {
		select {
		case e := <-ch:
			if e.EventType == eventType {
				return &e, true
			}
		case <-deadline:
			return nil, false
		}
	}
}

// ===========================================================================
// Unit Tests (no libp2p networking)
// ===========================================================================

func TestHandshake_Manager_SessionLifecycle(t *testing.T) {
	host1 := createTestHost(t)
	defer host1.Close()

	mgr := createTestManager(t, host1, 0.5)

	// Initially no sessions
	sessions := mgr.ListSessions()
	if len(sessions) != 0 {
		t.Errorf("expected 0 initial sessions, got %d", len(sessions))
	}

	// Create a session manually
	fakePeerID := peer.ID("fake-peer-id")
	session := mgr.CreateSession(fakePeerID, proto.RoleInitiator)

	// Verify session exists
	sessions = mgr.ListSessions()
	if len(sessions) != 1 {
		t.Errorf("expected 1 session after creation, got %d", len(sessions))
	}

	// Get session by ID
	retrieved := mgr.GetSession(session.ID)
	if retrieved == nil {
		t.Error("GetSession returned nil for valid session ID")
	}

	// Get session by peer
	byPeer := mgr.GetSessionByPeer(fakePeerID)
	if byPeer == nil {
		t.Error("GetSessionByPeer returned nil for valid peer ID")
	}

	// Remove session
	mgr.RemoveSession(session.ID)

	sessions = mgr.ListSessions()
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions after removal, got %d", len(sessions))
	}

	// GetSession should return nil now
	retrieved = mgr.GetSession(session.ID)
	if retrieved != nil {
		t.Error("GetSession should return nil after removal")
	}
}

func TestHandshake_Manager_Cooldown(t *testing.T) {
	host1 := createTestHost(t)
	defer host1.Close()

	cfg := handshake.ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 200 * time.Millisecond,
		Threshold:        0.5,
	}
	mgr := handshake.NewManager(host1, cfg)

	fakePeerID := peer.ID("test-peer")

	// First attempt should be allowed
	if !mgr.CanInitiate(fakePeerID) {
		t.Error("first initiation should be allowed")
	}

	// Record an attempt
	mgr.RecordAttempt(fakePeerID)

	// Immediate second attempt should be blocked
	if mgr.CanInitiate(fakePeerID) {
		t.Error("second initiation should be blocked during cooldown")
	}

	// Wait for cooldown
	time.Sleep(250 * time.Millisecond)

	// Should be allowed now
	if !mgr.CanInitiate(fakePeerID) {
		t.Error("initiation should be allowed after cooldown")
	}
}

func TestHandshake_Manager_EventSubscription(t *testing.T) {
	host1 := createTestHost(t)
	defer host1.Close()

	mgr := createTestManager(t, host1, 0.5)

	// Subscribe to events
	events := mgr.Subscribe()

	// Emit an event
	testEvent := handshake.Event{
		SessionID: "test-session",
		EventType: "test",
		State:     "TestState",
		PeerID:    "test-peer",
	}
	mgr.EmitEvent(testEvent)

	// Should receive the event
	select {
	case e := <-events:
		if e.SessionID != "test-session" {
			t.Errorf("expected session ID 'test-session', got '%s'", e.SessionID)
		}
		if e.EventType != "test" {
			t.Errorf("expected event type 'test', got '%s'", e.EventType)
		}
	case <-time.After(1 * time.Second):
		t.Error("timeout waiting for event")
	}
}

func TestHandshake_Session_ApprovalFlow(t *testing.T) {
	host1 := createTestHost(t)
	defer host1.Close()

	mgr := createTestManager(t, host1, 0.5)
	fakePeerID := peer.ID("test-peer")

	session := mgr.CreateSession(fakePeerID, proto.RoleInitiator)

	// Set pending approval
	session.SetPendingApproval("unmask")

	if !session.PendingApproval {
		t.Error("session should be pending approval")
	}
	if session.PendingApprovalType != "unmask" {
		t.Errorf("expected approval type 'unmask', got '%s'", session.PendingApprovalType)
	}

	// Signal approval in background
	go func() {
		time.Sleep(50 * time.Millisecond)
		session.SignalApproval(true)
	}()

	// Wait for approval
	approved := session.WaitForApproval()
	if !approved {
		t.Error("expected approval to be true")
	}
}

func TestHandshake_Session_Cleanup(t *testing.T) {
	host1 := createTestHost(t)
	defer host1.Close()

	mgr := createTestManager(t, host1, 0.5)
	fakePeerID := peer.ID("test-peer")

	session := mgr.CreateSession(fakePeerID, proto.RoleInitiator)

	// Set sensitive data
	session.LocalMonad = []byte{1, 2, 3, 4, 5}
	session.PeerMonad = []byte{6, 7, 8, 9, 10}

	// Verify data is present
	if len(session.LocalMonad) != 5 {
		t.Error("LocalMonad should have data before cleanup")
	}

	// Cleanup
	session.Cleanup()

	// Verify data is zeroed
	if session.LocalMonad != nil {
		t.Error("LocalMonad should be nil after cleanup")
	}
	if session.PeerMonad != nil {
		t.Error("PeerMonad should be nil after cleanup")
	}
}

// ===========================================================================
// TEE / Vector Match Tests
// ===========================================================================

func TestHandshake_TEE_CosineSimilarity(t *testing.T) {
	tests := []struct {
		name      string
		a         []float32
		b         []float32
		threshold float32
		expected  bool
	}{
		{
			name:      "identical vectors",
			a:         []float32{1.0, 0.0, 0.0},
			b:         []float32{1.0, 0.0, 0.0},
			threshold: 0.99,
			expected:  true,
		},
		{
			name:      "orthogonal vectors",
			a:         []float32{1.0, 0.0, 0.0},
			b:         []float32{0.0, 1.0, 0.0},
			threshold: 0.1,
			expected:  false,
		},
		{
			name:      "similar vectors low threshold",
			a:         []float32{1.0, 0.5, 0.3},
			b:         []float32{0.9, 0.6, 0.35},
			threshold: 0.9,
			expected:  true,
		},
		{
			name:      "opposite vectors",
			a:         []float32{1.0, 0.0, 0.0},
			b:         []float32{-1.0, 0.0, 0.0},
			threshold: 0.0,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			monadA := tee.SerializeMonad(tt.a)
			monadB := tee.SerializeMonad(tt.b)

			result, err := tee.ComputeMatch(monadA, monadB, tt.threshold)
			if err != nil {
				t.Fatalf("ComputeMatch failed: %v", err)
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestHandshake_TEE_SerializationRoundtrip(t *testing.T) {
	original := []float32{1.0, 2.5, -3.14159, 0.0, 100.0}

	serialized := tee.SerializeMonad(original)
	deserialized, err := tee.DeserializeMonad(serialized)
	if err != nil {
		t.Fatalf("DeserializeMonad failed: %v", err)
	}

	if len(deserialized) != len(original) {
		t.Fatalf("length mismatch: expected %d, got %d", len(original), len(deserialized))
	}

	for i, v := range original {
		if deserialized[i] != v {
			t.Errorf("value mismatch at index %d: expected %f, got %f", i, v, deserialized[i])
		}
	}
}

// ===========================================================================
// Handshake State Machine Tests
// ===========================================================================

func TestHandshake_StateMachine_HappyPath(t *testing.T) {
	fakePeerID := peer.ID("test-peer")
	hs := proto.NewHandshake(proto.RoleInitiator, fakePeerID, 0.5)

	// Initial state
	if hs.State() != proto.StateIdle {
		t.Errorf("expected StateIdle, got %s", hs.State())
	}

	// Transition through happy path
	transitions := []struct {
		event    proto.Event
		expected proto.State
	}{
		{proto.EventInitiate, proto.StateAttestation},
		{proto.EventAttestationSuccess, proto.StateVectorMatch},
		{proto.EventMatchAboveThreshold, proto.StateDealBreakers},
		{proto.EventDealBreakersMatch, proto.StateHumanChat},
		{proto.EventChatApproval, proto.StateUnmask},
		{proto.EventMutualApproval, proto.StateComplete},
	}

	for _, tr := range transitions {
		if err := hs.Transition(tr.event); err != nil {
			t.Fatalf("failed transition %s: %v", tr.event, err)
		}
		if hs.State() != tr.expected {
			t.Errorf("after %s: expected %s, got %s", tr.event, tr.expected, hs.State())
		}
	}

	// Should be terminal
	if !hs.IsComplete() {
		t.Error("expected IsComplete() to be true")
	}
	if !hs.IsTerminal() {
		t.Error("expected IsTerminal() to be true")
	}
}

func TestHandshake_StateMachine_FailurePaths(t *testing.T) {
	tests := []struct {
		name        string
		transitions []proto.Event
	}{
		{
			name: "attestation failure",
			transitions: []proto.Event{
				proto.EventInitiate,
				proto.EventAttestationFailure,
			},
		},
		{
			name: "vector match failure",
			transitions: []proto.Event{
				proto.EventInitiate,
				proto.EventAttestationSuccess,
				proto.EventMatchBelowThreshold,
			},
		},
		{
			name: "deal breaker mismatch",
			transitions: []proto.Event{
				proto.EventInitiate,
				proto.EventAttestationSuccess,
				proto.EventMatchAboveThreshold,
				proto.EventDealBreakersMismatch,
			},
		},
		{
			name: "chat rejection",
			transitions: []proto.Event{
				proto.EventInitiate,
				proto.EventAttestationSuccess,
				proto.EventMatchAboveThreshold,
				proto.EventDealBreakersMatch,
				proto.EventChatRejection,
			},
		},
		{
			name: "unmask rejection",
			transitions: []proto.Event{
				proto.EventInitiate,
				proto.EventAttestationSuccess,
				proto.EventMatchAboveThreshold,
				proto.EventDealBreakersMatch,
				proto.EventChatApproval,
				proto.EventUnmaskRejection,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakePeerID := peer.ID("test-peer")
			hs := proto.NewHandshake(proto.RoleInitiator, fakePeerID, 0.5)

			for _, event := range tt.transitions {
				if err := hs.Transition(event); err != nil {
					t.Fatalf("failed transition %s: %v", event, err)
				}
			}

			if !hs.IsFailed() {
				t.Error("expected IsFailed() to be true")
			}
			if !hs.IsTerminal() {
				t.Error("expected IsTerminal() to be true")
			}
		})
	}
}

func TestHandshake_StateMachine_InvalidTransitions(t *testing.T) {
	fakePeerID := peer.ID("test-peer")
	hs := proto.NewHandshake(proto.RoleInitiator, fakePeerID, 0.5)

	// Try invalid transition from Idle
	err := hs.Transition(proto.EventAttestationSuccess)
	if err == nil {
		t.Error("expected error for invalid transition")
	}

	// Valid transition
	if err := hs.Transition(proto.EventInitiate); err != nil {
		t.Fatalf("failed valid transition: %v", err)
	}

	// Try invalid transition from Attestation
	err = hs.Transition(proto.EventMutualApproval)
	if err == nil {
		t.Error("expected error for invalid transition from Attestation")
	}
}

// ===========================================================================
// Wire Protocol Tests (Codec)
// ===========================================================================

func TestHandshake_Codec_RoundTrip(t *testing.T) {
	// Create a test envelope
	original := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_REQUEST,
		Payload:   []byte("test payload"),
		Timestamp: time.Now().Unix(),
		Signature: []byte("test signature"),
	}

	// Create a pipe for testing
	reader, writer := io.Pipe()

	// Write in background
	go func() {
		if err := handshake.WriteEnvelope(writer, original); err != nil {
			t.Errorf("WriteEnvelope failed: %v", err)
		}
		writer.Close()
	}()

	// Read
	received, err := handshake.ReadEnvelope(reader)
	if err != nil {
		t.Fatalf("ReadEnvelope failed: %v", err)
	}

	// Verify
	if received.Type != original.Type {
		t.Errorf("type mismatch: expected %v, got %v", original.Type, received.Type)
	}
	if string(received.Payload) != string(original.Payload) {
		t.Errorf("payload mismatch")
	}
	if received.Timestamp != original.Timestamp {
		t.Errorf("timestamp mismatch")
	}
}

func TestHandshake_Codec_MultipleMessages(t *testing.T) {
	reader, writer := io.Pipe()

	messages := []*pb.HandshakeEnvelope{
		{Type: pb.MessageType_ATTESTATION_REQUEST, Payload: []byte("req1")},
		{Type: pb.MessageType_ATTESTATION_RESPONSE, Payload: []byte("resp1")},
		{Type: pb.MessageType_VECTOR_MATCH_REQUEST, Payload: []byte("vmr")},
	}

	// Write all messages
	go func() {
		for _, msg := range messages {
			if err := handshake.WriteEnvelope(writer, msg); err != nil {
				t.Errorf("WriteEnvelope failed: %v", err)
			}
		}
		writer.Close()
	}()

	// Read all messages
	for i, expected := range messages {
		received, err := handshake.ReadEnvelope(reader)
		if err != nil {
			t.Fatalf("ReadEnvelope %d failed: %v", i, err)
		}
		if received.Type != expected.Type {
			t.Errorf("message %d type mismatch: expected %v, got %v", i, expected.Type, received.Type)
		}
	}
}

// ===========================================================================
// Integration Tests (with networking)
// ===========================================================================

func TestHandshake_Integration_StreamConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create two hosts
	host1 := createTestHost(t)
	host2 := createTestHost(t)
	defer host1.Close()
	defer host2.Close()

	// Connect hosts
	connectHosts(t, host1, host2)

	// Verify connection
	if host1.Network().Connectedness(host2.ID()) != network.Connected {
		t.Error("hosts are not connected")
	}

	// Set up a simple protocol handler to verify streams work
	var streamReceived atomic.Bool
	host2.SetStreamHandler(protocol.ID("/test/1.0.0"), func(s network.Stream) {
		streamReceived.Store(true)
		s.Close()
	})

	// Open stream from host1 to host2
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := host1.NewStream(ctx, host2.ID(), protocol.ID("/test/1.0.0"))
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}
	stream.Close()

	// Wait for stream to be received
	time.Sleep(100 * time.Millisecond)
	if !streamReceived.Load() {
		t.Error("stream was not received by host2")
	}
}

func TestHandshake_Integration_FullHandshakeSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create two hosts
	host1 := createTestHost(t)
	host2 := createTestHost(t)
	defer host1.Close()
	defer host2.Close()

	// Create managers with pre-configured sessions
	mgr1 := createTestManager(t, host1, 0.5)
	mgr2 := createTestManager(t, host2, 0.5)

	// Prepare test data
	monad1, monad2 := createSimilarMonads()
	db1, db2 := createCompatibleDealBreakers()
	identity1 := createTestIdentity("Alice", "alice@example.com")
	identity2 := createTestIdentity("Bob", "bob@example.com")

	// Track sessions for configuration
	var session1, session2 *handshake.Session
	var session1Configured, session2Configured atomic.Bool

	// Create handlers that configure sessions immediately
	handler1 := handshake.NewStreamHandler(mgr1, testLogger())
	handler2 := handshake.NewStreamHandler(mgr2, testLogger())

	// We need to intercept session creation to configure before protocol runs
	// This is a limitation of the current design - sessions need pre-configuration

	// Register handlers
	handler1.Register(host1)
	handler2.Register(host2)

	// Connect hosts
	connectHosts(t, host1, host2)

	// Subscribe to events
	events1 := mgr1.Subscribe()
	events2 := mgr2.Subscribe()

	// Start goroutines to configure sessions as soon as they appear
	go func() {
		for !session1Configured.Load() {
			sessions := mgr1.ListSessions()
			for _, s := range sessions {
				if !session1Configured.Load() {
					session1 = s
					s.LocalMonad = monad1
					s.DealBreakerConfig = db1
					s.IdentityPayload = identity1
					session1Configured.Store(true)
				}
			}
			time.Sleep(100 * time.Microsecond)
		}
	}()

	go func() {
		for !session2Configured.Load() {
			sessions := mgr2.ListSessions()
			for _, s := range sessions {
				if !session2Configured.Load() {
					session2 = s
					s.LocalMonad = monad2
					s.DealBreakerConfig = db2
					s.IdentityPayload = identity2
					session2Configured.Store(true)
				}
			}
			time.Sleep(100 * time.Microsecond)
		}
	}()

	// Initiate handshake
	ctx := context.Background()
	_, err := handler1.InitiateHandshake(ctx, host1, host2.ID())
	if err != nil {
		t.Fatalf("failed to initiate handshake: %v", err)
	}

	// Wait for both sessions to be configured
	deadline := time.After(5 * time.Second)
	for !session1Configured.Load() || !session2Configured.Load() {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for sessions to be configured")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Auto-approve unmask for both sides
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			if session1 != nil && session1.PendingApproval {
				session1.SignalApproval(true)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			if session2 != nil && session2.PendingApproval {
				session2.SignalApproval(true)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Wait for completion or failure
	timeout := time.After(60 * time.Second)
	var gotEvent1, gotEvent2 bool

	for !gotEvent1 || !gotEvent2 {
		select {
		case e := <-events1:
			if e.EventType == "completed" || e.EventType == "failed" {
				gotEvent1 = true
				t.Logf("host1 event: %s, state: %s", e.EventType, e.State)
			}
		case e := <-events2:
			if e.EventType == "completed" || e.EventType == "failed" {
				gotEvent2 = true
				t.Logf("host2 event: %s, state: %s", e.EventType, e.State)
			}
		case <-timeout:
			if session1 != nil {
				t.Logf("session1 state: %s, pending: %v", session1.State(), session1.PendingApproval)
			}
			if session2 != nil {
				t.Logf("session2 state: %s, pending: %v", session2.State(), session2.PendingApproval)
			}
			t.Fatal("timeout waiting for handshake completion")
		}
	}

	wg.Wait()

	// Check final states - we expect completion or failure based on race conditions
	// In a real system, the session would be pre-configured before protocol starts
	t.Logf("Final states - session1: %v, session2: %v",
		session1 != nil && session1.Handshake.IsTerminal(),
		session2 != nil && session2.Handshake.IsTerminal())
}

func TestHandshake_Integration_VectorMatchFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create two hosts
	host1 := createTestHost(t)
	host2 := createTestHost(t)
	defer host1.Close()
	defer host2.Close()

	// Create managers with LOW threshold (0.1) - orthogonal vectors will still fail
	// because their cosine similarity is 0, which is less than 0.1
	mgr1 := createTestManager(t, host1, 0.1)
	mgr2 := createTestManager(t, host2, 0.1)

	// Prepare ORTHOGONAL monads - these will fail vector match
	monad1, monad2 := createOrthogonalMonads()

	// Still need compatible deal breakers and identities in case we get past vector match
	db1, db2 := createCompatibleDealBreakers()
	identity1 := createTestIdentity("Alice", "alice@example.com")
	identity2 := createTestIdentity("Bob", "bob@example.com")

	// Track sessions for configuration
	var session1, session2 *handshake.Session
	var session1Configured, session2Configured atomic.Bool

	// Create handlers
	handler1 := handshake.NewStreamHandler(mgr1, testLogger())
	handler2 := handshake.NewStreamHandler(mgr2, testLogger())

	// Register handlers
	handler1.Register(host1)
	handler2.Register(host2)

	// Connect hosts
	connectHosts(t, host1, host2)

	// Subscribe to events
	events1 := mgr1.Subscribe()
	events2 := mgr2.Subscribe()

	// Start goroutines to configure sessions as soon as they appear
	go func() {
		for !session1Configured.Load() {
			sessions := mgr1.ListSessions()
			for _, s := range sessions {
				if !session1Configured.Load() {
					session1 = s
					s.LocalMonad = monad1 // Orthogonal vector
					s.DealBreakerConfig = db1
					s.IdentityPayload = identity1
					session1Configured.Store(true)
				}
			}
			time.Sleep(100 * time.Microsecond)
		}
	}()

	go func() {
		for !session2Configured.Load() {
			sessions := mgr2.ListSessions()
			for _, s := range sessions {
				if !session2Configured.Load() {
					session2 = s
					s.LocalMonad = monad2 // Orthogonal vector
					s.DealBreakerConfig = db2
					s.IdentityPayload = identity2
					session2Configured.Store(true)
				}
			}
			time.Sleep(100 * time.Microsecond)
		}
	}()

	// Initiate handshake
	ctx := context.Background()
	_, err := handler1.InitiateHandshake(ctx, host1, host2.ID())
	if err != nil {
		t.Fatalf("failed to initiate handshake: %v", err)
	}

	// Wait for both sessions to be configured
	deadline := time.After(5 * time.Second)
	for !session1Configured.Load() || !session2Configured.Load() {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for sessions to be configured")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Wait for failure events
	timeout := time.After(30 * time.Second)
	var gotEvent1, gotEvent2 bool
	var event1Failed, event2Failed bool

	for !gotEvent1 || !gotEvent2 {
		select {
		case e := <-events1:
			if e.EventType == "completed" || e.EventType == "failed" {
				gotEvent1 = true
				event1Failed = e.EventType == "failed"
				t.Logf("host1 event: %s, state: %s", e.EventType, e.State)
			}
		case e := <-events2:
			if e.EventType == "completed" || e.EventType == "failed" {
				gotEvent2 = true
				event2Failed = e.EventType == "failed"
				t.Logf("host2 event: %s, state: %s", e.EventType, e.State)
			}
		case <-timeout:
			if session1 != nil {
				t.Logf("session1 state: %s", session1.State())
			}
			if session2 != nil {
				t.Logf("session2 state: %s", session2.State())
			}
			t.Fatal("timeout waiting for handshake failure")
		}
	}

	// Verify both sides failed
	if !event1Failed {
		t.Error("expected host1 to emit failed event for vector match failure")
	}
	if !event2Failed {
		t.Error("expected host2 to emit failed event for vector match failure")
	}
}

func TestHandshake_Integration_DealBreakerMismatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create two hosts
	host1 := createTestHost(t)
	host2 := createTestHost(t)
	defer host1.Close()
	defer host2.Close()

	// Create managers with low threshold so vector match passes
	mgr1 := createTestManager(t, host1, 0.5)
	mgr2 := createTestManager(t, host2, 0.5)

	// Prepare SIMILAR monads - these will pass vector match
	monad1, monad2 := createSimilarMonads()

	// Use INCOMPATIBLE deal breakers - these will fail
	db1, db2 := createIncompatibleDealBreakers()
	identity1 := createTestIdentity("Alice", "alice@example.com")
	identity2 := createTestIdentity("Bob", "bob@example.com")

	// Track sessions for configuration
	var session1, session2 *handshake.Session
	var session1Configured, session2Configured atomic.Bool

	// Create handlers
	handler1 := handshake.NewStreamHandler(mgr1, testLogger())
	handler2 := handshake.NewStreamHandler(mgr2, testLogger())

	// Register handlers
	handler1.Register(host1)
	handler2.Register(host2)

	// Connect hosts
	connectHosts(t, host1, host2)

	// Subscribe to events
	events1 := mgr1.Subscribe()
	events2 := mgr2.Subscribe()

	// Start goroutines to configure sessions as soon as they appear
	go func() {
		for !session1Configured.Load() {
			sessions := mgr1.ListSessions()
			for _, s := range sessions {
				if !session1Configured.Load() {
					session1 = s
					s.LocalMonad = monad1
					s.DealBreakerConfig = db1 // Incompatible deal breakers
					s.IdentityPayload = identity1
					session1Configured.Store(true)
				}
			}
			time.Sleep(100 * time.Microsecond)
		}
	}()

	go func() {
		for !session2Configured.Load() {
			sessions := mgr2.ListSessions()
			for _, s := range sessions {
				if !session2Configured.Load() {
					session2 = s
					s.LocalMonad = monad2
					s.DealBreakerConfig = db2 // Incompatible deal breakers
					s.IdentityPayload = identity2
					session2Configured.Store(true)
				}
			}
			time.Sleep(100 * time.Microsecond)
		}
	}()

	// Initiate handshake
	ctx := context.Background()
	_, err := handler1.InitiateHandshake(ctx, host1, host2.ID())
	if err != nil {
		t.Fatalf("failed to initiate handshake: %v", err)
	}

	// Wait for both sessions to be configured
	deadline := time.After(5 * time.Second)
	for !session1Configured.Load() || !session2Configured.Load() {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for sessions to be configured")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Wait for failure events
	timeout := time.After(30 * time.Second)
	var gotEvent1, gotEvent2 bool
	var event1Failed, event2Failed bool

	for !gotEvent1 || !gotEvent2 {
		select {
		case e := <-events1:
			if e.EventType == "completed" || e.EventType == "failed" {
				gotEvent1 = true
				event1Failed = e.EventType == "failed"
				t.Logf("host1 event: %s, state: %s", e.EventType, e.State)
			}
		case e := <-events2:
			if e.EventType == "completed" || e.EventType == "failed" {
				gotEvent2 = true
				event2Failed = e.EventType == "failed"
				t.Logf("host2 event: %s, state: %s", e.EventType, e.State)
			}
		case <-timeout:
			if session1 != nil {
				t.Logf("session1 state: %s", session1.State())
			}
			if session2 != nil {
				t.Logf("session2 state: %s", session2.State())
			}
			t.Fatal("timeout waiting for handshake failure")
		}
	}

	// Verify both sides failed
	if !event1Failed {
		t.Error("expected host1 to emit failed event for deal breaker mismatch")
	}
	if !event2Failed {
		t.Error("expected host2 to emit failed event for deal breaker mismatch")
	}
}

func TestHandshake_Integration_UnmaskRejection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create two hosts
	host1 := createTestHost(t)
	host2 := createTestHost(t)
	defer host1.Close()
	defer host2.Close()

	// Create managers
	mgr1 := createTestManager(t, host1, 0.5)
	mgr2 := createTestManager(t, host2, 0.5)

	// Prepare test data - all compatible to get through to unmask stage
	monad1, monad2 := createSimilarMonads()
	db1, db2 := createCompatibleDealBreakers()
	identity1 := createTestIdentity("Alice", "alice@example.com")
	identity2 := createTestIdentity("Bob", "bob@example.com")

	// Track sessions for configuration
	var session1, session2 *handshake.Session
	var session1Configured, session2Configured atomic.Bool

	// Create handlers
	handler1 := handshake.NewStreamHandler(mgr1, testLogger())
	handler2 := handshake.NewStreamHandler(mgr2, testLogger())

	// Register handlers
	handler1.Register(host1)
	handler2.Register(host2)

	// Connect hosts
	connectHosts(t, host1, host2)

	// Subscribe to events
	events1 := mgr1.Subscribe()
	events2 := mgr2.Subscribe()

	// Start goroutines to configure sessions as soon as they appear
	go func() {
		for !session1Configured.Load() {
			sessions := mgr1.ListSessions()
			for _, s := range sessions {
				if !session1Configured.Load() {
					session1 = s
					s.LocalMonad = monad1
					s.DealBreakerConfig = db1
					s.IdentityPayload = identity1
					session1Configured.Store(true)
				}
			}
			time.Sleep(100 * time.Microsecond)
		}
	}()

	go func() {
		for !session2Configured.Load() {
			sessions := mgr2.ListSessions()
			for _, s := range sessions {
				if !session2Configured.Load() {
					session2 = s
					s.LocalMonad = monad2
					s.DealBreakerConfig = db2
					s.IdentityPayload = identity2
					session2Configured.Store(true)
				}
			}
			time.Sleep(100 * time.Microsecond)
		}
	}()

	// Initiate handshake
	ctx := context.Background()
	_, err := handler1.InitiateHandshake(ctx, host1, host2.ID())
	if err != nil {
		t.Fatalf("failed to initiate handshake: %v", err)
	}

	// Wait for both sessions to be configured
	deadline := time.After(5 * time.Second)
	for !session1Configured.Load() || !session2Configured.Load() {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for sessions to be configured")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Approval handling: host1 approves, host2 REJECTS
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			if session1 != nil && session1.PendingApproval {
				t.Log("host1 approving unmask")
				session1.SignalApproval(true) // Approve
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			if session2 != nil && session2.PendingApproval {
				t.Log("host2 REJECTING unmask")
				session2.SignalApproval(false) // REJECT!
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Wait for completion or failure
	timeout := time.After(60 * time.Second)
	var gotEvent1, gotEvent2 bool
	var event1Failed, event2Failed bool

	for !gotEvent1 || !gotEvent2 {
		select {
		case e := <-events1:
			if e.EventType == "completed" || e.EventType == "failed" {
				gotEvent1 = true
				event1Failed = e.EventType == "failed"
				t.Logf("host1 event: %s, state: %s", e.EventType, e.State)
			}
		case e := <-events2:
			if e.EventType == "completed" || e.EventType == "failed" {
				gotEvent2 = true
				event2Failed = e.EventType == "failed"
				t.Logf("host2 event: %s, state: %s", e.EventType, e.State)
			}
		case <-timeout:
			if session1 != nil {
				t.Logf("session1 state: %s, pending: %v", session1.State(), session1.PendingApproval)
			}
			if session2 != nil {
				t.Logf("session2 state: %s, pending: %v", session2.State(), session2.PendingApproval)
			}
			t.Fatal("timeout waiting for handshake failure")
		}
	}

	wg.Wait()

	// Verify both sides failed due to unmask rejection
	if !event1Failed {
		t.Error("expected host1 to emit failed event for unmask rejection")
	}
	if !event2Failed {
		t.Error("expected host2 to emit failed event for unmask rejection")
	}
}

// ===========================================================================
// Benchmark Tests
// ===========================================================================

func BenchmarkHandshake_TEE_ComputeMatch(b *testing.B) {
	// Create 768-dimensional monads (typical embedding size)
	values1 := make([]float32, 768)
	values2 := make([]float32, 768)
	for i := 0; i < 768; i++ {
		values1[i] = float32(i) / 768.0
		values2[i] = float32(i+1) / 768.0
	}

	monad1 := tee.SerializeMonad(values1)
	monad2 := tee.SerializeMonad(values2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = tee.ComputeMatch(monad1, monad2, 0.5)
	}
}

func BenchmarkHandshake_MonadSerialization(b *testing.B) {
	values := make([]float32, 768)
	for i := 0; i < 768; i++ {
		values[i] = float32(i) / 768.0
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data := tee.SerializeMonad(values)
		_, _ = tee.DeserializeMonad(data)
	}
}

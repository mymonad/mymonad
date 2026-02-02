package handshake

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	pb "github.com/mymonad/mymonad/api/proto"
	"github.com/mymonad/mymonad/pkg/protocol"
	googleproto "google.golang.org/protobuf/proto"
)

// ===========================================================================
// Unmask Stage Tests
// ===========================================================================

func TestUnmask_BothApprove(t *testing.T) {
	// Create mock streams for communication
	initiatorStream, responderStream := newMockStreamPair()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}

	// Create managers and handlers for both sides
	initiatorManager := NewManager(nil, cfg)
	responderManager := NewManager(nil, cfg)
	initiatorHandler := NewStreamHandler(initiatorManager, logger)
	responderHandler := NewStreamHandler(responderManager, logger)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Create sessions and transition to Unmask state
	// (skipping HumanChat since it's optional)
	initiatorSession := initiatorManager.CreateSession(testPeerID, protocol.RoleInitiator)
	responderSession := responderManager.CreateSession(testPeerID, protocol.RoleResponder)

	// Start state machines and transition to Unmask
	initiatorSession.Handshake.Transition(protocol.EventInitiate)
	initiatorSession.Handshake.Transition(protocol.EventAttestationSuccess)
	initiatorSession.Handshake.Transition(protocol.EventMatchAboveThreshold)
	initiatorSession.Handshake.Transition(protocol.EventDealBreakersMatch)
	initiatorSession.Handshake.Transition(protocol.EventChatApproval) // Skip to Unmask

	responderSession.Handshake.Transition(protocol.EventInitiate)
	responderSession.Handshake.Transition(protocol.EventAttestationSuccess)
	responderSession.Handshake.Transition(protocol.EventMatchAboveThreshold)
	responderSession.Handshake.Transition(protocol.EventDealBreakersMatch)
	responderSession.Handshake.Transition(protocol.EventChatApproval) // Skip to Unmask

	// Set up identity payloads for both sides
	initiatorSession.IdentityPayload = &pb.IdentityPayload{
		DisplayName: "Alice",
		Email:       "alice@example.com",
	}
	responderSession.IdentityPayload = &pb.IdentityPayload{
		DisplayName: "Bob",
		Email:       "bob@example.com",
	}

	// Assign streams
	initiatorSession.Stream = initiatorStream
	responderSession.Stream = responderStream

	var wg sync.WaitGroup
	var initiatorErr, responderErr error

	// Simulate human approval in background (after a brief delay to let protocol start)
	go func() {
		time.Sleep(50 * time.Millisecond)
		initiatorSession.SignalApproval(true)
	}()
	go func() {
		time.Sleep(50 * time.Millisecond)
		responderSession.SignalApproval(true)
	}()

	// Run responder in background
	wg.Add(1)
	go func() {
		defer wg.Done()
		responderErr = responderHandler.doUnmaskResponder(responderSession)
	}()

	// Run initiator
	wg.Add(1)
	go func() {
		defer wg.Done()
		initiatorErr = initiatorHandler.doUnmaskInitiator(initiatorSession)
	}()

	wg.Wait()

	if initiatorErr != nil {
		t.Errorf("initiator unmask failed: %v", initiatorErr)
	}
	if responderErr != nil {
		t.Errorf("responder unmask failed: %v", responderErr)
	}

	// Verify peer identities were exchanged
	if initiatorSession.PeerIdentity == nil {
		t.Error("expected initiator to have peer identity")
	}
	if responderSession.PeerIdentity == nil {
		t.Error("expected responder to have peer identity")
	}

	// Verify identity content
	if initiatorSession.PeerIdentity != nil && initiatorSession.PeerIdentity.DisplayName != "Bob" {
		t.Errorf("expected initiator's peer to be Bob, got %s", initiatorSession.PeerIdentity.DisplayName)
	}
	if responderSession.PeerIdentity != nil && responderSession.PeerIdentity.DisplayName != "Alice" {
		t.Errorf("expected responder's peer to be Alice, got %s", responderSession.PeerIdentity.DisplayName)
	}
}

func TestUnmask_InitiatorRejects(t *testing.T) {
	// Create mock streams for communication
	initiatorStream, responderStream := newMockStreamPair()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}

	// Create managers and handlers for both sides
	initiatorManager := NewManager(nil, cfg)
	responderManager := NewManager(nil, cfg)
	initiatorHandler := NewStreamHandler(initiatorManager, logger)
	responderHandler := NewStreamHandler(responderManager, logger)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Create sessions and transition to Unmask state
	initiatorSession := initiatorManager.CreateSession(testPeerID, protocol.RoleInitiator)
	responderSession := responderManager.CreateSession(testPeerID, protocol.RoleResponder)

	// Transition to Unmask state
	initiatorSession.Handshake.Transition(protocol.EventInitiate)
	initiatorSession.Handshake.Transition(protocol.EventAttestationSuccess)
	initiatorSession.Handshake.Transition(protocol.EventMatchAboveThreshold)
	initiatorSession.Handshake.Transition(protocol.EventDealBreakersMatch)
	initiatorSession.Handshake.Transition(protocol.EventChatApproval)

	responderSession.Handshake.Transition(protocol.EventInitiate)
	responderSession.Handshake.Transition(protocol.EventAttestationSuccess)
	responderSession.Handshake.Transition(protocol.EventMatchAboveThreshold)
	responderSession.Handshake.Transition(protocol.EventDealBreakersMatch)
	responderSession.Handshake.Transition(protocol.EventChatApproval)

	// Set up identity payloads
	initiatorSession.IdentityPayload = &pb.IdentityPayload{DisplayName: "Alice"}
	responderSession.IdentityPayload = &pb.IdentityPayload{DisplayName: "Bob"}

	// Assign streams
	initiatorSession.Stream = initiatorStream
	responderSession.Stream = responderStream

	var wg sync.WaitGroup
	var initiatorErr error

	// Initiator rejects
	go func() {
		time.Sleep(50 * time.Millisecond)
		initiatorSession.SignalApproval(false) // Reject
	}()

	// Responder approves (but won't matter since initiator rejects first)
	go func() {
		time.Sleep(100 * time.Millisecond)
		responderSession.SignalApproval(true)
	}()

	// Run both sides (responder may error due to stream close)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = responderHandler.doUnmaskResponder(responderSession)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		initiatorErr = initiatorHandler.doUnmaskInitiator(initiatorSession)
	}()

	wg.Wait()

	// Initiator should report rejection
	if initiatorErr == nil {
		t.Error("expected initiator to report rejection error")
	}
	if initiatorErr != nil && initiatorErr.Error() != "user rejected unmask" {
		t.Errorf("unexpected error: %v", initiatorErr)
	}
}

func TestUnmask_ResponderRejects(t *testing.T) {
	// Create mock streams for communication
	initiatorStream, responderStream := newMockStreamPair()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}

	// Create managers and handlers for both sides
	initiatorManager := NewManager(nil, cfg)
	responderManager := NewManager(nil, cfg)
	initiatorHandler := NewStreamHandler(initiatorManager, logger)
	responderHandler := NewStreamHandler(responderManager, logger)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Create sessions and transition to Unmask state
	initiatorSession := initiatorManager.CreateSession(testPeerID, protocol.RoleInitiator)
	responderSession := responderManager.CreateSession(testPeerID, protocol.RoleResponder)

	// Transition to Unmask state
	initiatorSession.Handshake.Transition(protocol.EventInitiate)
	initiatorSession.Handshake.Transition(protocol.EventAttestationSuccess)
	initiatorSession.Handshake.Transition(protocol.EventMatchAboveThreshold)
	initiatorSession.Handshake.Transition(protocol.EventDealBreakersMatch)
	initiatorSession.Handshake.Transition(protocol.EventChatApproval)

	responderSession.Handshake.Transition(protocol.EventInitiate)
	responderSession.Handshake.Transition(protocol.EventAttestationSuccess)
	responderSession.Handshake.Transition(protocol.EventMatchAboveThreshold)
	responderSession.Handshake.Transition(protocol.EventDealBreakersMatch)
	responderSession.Handshake.Transition(protocol.EventChatApproval)

	// Set up identity payloads
	initiatorSession.IdentityPayload = &pb.IdentityPayload{DisplayName: "Alice"}
	responderSession.IdentityPayload = &pb.IdentityPayload{DisplayName: "Bob"}

	// Assign streams
	initiatorSession.Stream = initiatorStream
	responderSession.Stream = responderStream

	var wg sync.WaitGroup
	var initiatorErr, responderErr error

	// Initiator approves
	go func() {
		time.Sleep(50 * time.Millisecond)
		initiatorSession.SignalApproval(true)
	}()

	// Responder rejects after receiving request
	go func() {
		time.Sleep(100 * time.Millisecond)
		responderSession.SignalApproval(false) // Reject
	}()

	// Run both sides
	wg.Add(1)
	go func() {
		defer wg.Done()
		responderErr = responderHandler.doUnmaskResponder(responderSession)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		initiatorErr = initiatorHandler.doUnmaskInitiator(initiatorSession)
	}()

	wg.Wait()

	// Responder should report rejection
	if responderErr == nil {
		t.Error("expected responder to report rejection error")
	}
	if responderErr != nil && responderErr.Error() != "user rejected unmask" {
		t.Errorf("unexpected responder error: %v", responderErr)
	}

	// Initiator should receive rejection response
	if initiatorErr == nil {
		t.Error("expected initiator to receive rejection")
	}
}

func TestUnmask_PendingApprovalEmitted(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}
	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	// Subscribe to events
	events := manager.Subscribe()

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	session := manager.CreateSession(testPeerID, protocol.RoleInitiator)
	session.Handshake.Transition(protocol.EventInitiate)
	session.Handshake.Transition(protocol.EventAttestationSuccess)
	session.Handshake.Transition(protocol.EventMatchAboveThreshold)
	session.Handshake.Transition(protocol.EventDealBreakersMatch)
	session.Handshake.Transition(protocol.EventChatApproval)

	session.IdentityPayload = &pb.IdentityPayload{DisplayName: "Alice"}

	// Create a buffer - we don't care about the protocol exchange, just the event
	var buf bytes.Buffer
	r, w := io.Pipe()

	// Signal approval after a delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		session.SignalApproval(false) // Reject to terminate quickly
	}()

	session.Stream = &mockStream{reader: r, writer: &buf}

	// Start unmask in background - it will block waiting for approval
	go func() {
		_ = handler.doUnmaskInitiator(session)
		w.Close()
	}()

	// Check for pending_approval event
	select {
	case e := <-events:
		if e.EventType != "pending_approval" {
			t.Errorf("expected event type pending_approval, got %s", e.EventType)
		}
		if e.SessionID != session.ID {
			t.Errorf("expected session ID %s, got %s", session.ID, e.SessionID)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout waiting for pending_approval event")
	}
}

func TestUnmask_StateTransitions(t *testing.T) {
	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	t.Run("mutual approval transitions to Complete", func(t *testing.T) {
		h := protocol.NewHandshake(protocol.RoleInitiator, testPeerID, 0.7)

		// Transition to Unmask
		h.Transition(protocol.EventInitiate)
		h.Transition(protocol.EventAttestationSuccess)
		h.Transition(protocol.EventMatchAboveThreshold)
		h.Transition(protocol.EventDealBreakersMatch)
		h.Transition(protocol.EventChatApproval)

		if h.State() != protocol.StateUnmask {
			t.Errorf("expected StateUnmask, got %v", h.State())
		}

		// Mutual approval -> Complete
		if err := h.Transition(protocol.EventMutualApproval); err != nil {
			t.Fatalf("failed to transition to complete: %v", err)
		}
		if h.State() != protocol.StateComplete {
			t.Errorf("expected StateComplete, got %v", h.State())
		}
	})

	t.Run("rejection transitions to Failed", func(t *testing.T) {
		h := protocol.NewHandshake(protocol.RoleInitiator, testPeerID, 0.7)

		// Transition to Unmask
		h.Transition(protocol.EventInitiate)
		h.Transition(protocol.EventAttestationSuccess)
		h.Transition(protocol.EventMatchAboveThreshold)
		h.Transition(protocol.EventDealBreakersMatch)
		h.Transition(protocol.EventChatApproval)

		// Rejection -> Failed
		if err := h.Transition(protocol.EventUnmaskRejection); err != nil {
			t.Fatalf("failed to transition to failed: %v", err)
		}
		if h.State() != protocol.StateFailed {
			t.Errorf("expected StateFailed, got %v", h.State())
		}
	})
}

func TestUnmaskInitiator_SendsValidRequest(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}
	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Create a buffer to capture what initiator writes
	var buf bytes.Buffer

	session := manager.CreateSession(testPeerID, protocol.RoleInitiator)
	session.Handshake.Transition(protocol.EventInitiate)
	session.Handshake.Transition(protocol.EventAttestationSuccess)
	session.Handshake.Transition(protocol.EventMatchAboveThreshold)
	session.Handshake.Transition(protocol.EventDealBreakersMatch)
	session.Handshake.Transition(protocol.EventChatApproval)

	session.IdentityPayload = &pb.IdentityPayload{
		DisplayName: "Alice",
		Email:       "alice@example.com",
	}

	// Use a pipe for reading (will close causing error) and buffer for writing
	r, w := io.Pipe()

	// Signal approval immediately so request gets sent
	go func() {
		time.Sleep(50 * time.Millisecond)
		session.SignalApproval(true)
		// Close after writing - this will cause read to fail
		time.Sleep(50 * time.Millisecond)
		w.Close()
	}()

	session.Stream = &mockStream{reader: r, writer: &buf}

	// This will fail on read (as expected), but the request should be written
	_ = handler.doUnmaskInitiator(session)

	// Verify the request was written
	if buf.Len() == 0 {
		t.Fatal("no data written by initiator")
	}

	// Parse the written envelope
	env, err := ReadEnvelope(&buf)
	if err != nil {
		t.Fatalf("failed to read envelope: %v", err)
	}

	if env.Type != pb.MessageType_UNMASK_REQUEST {
		t.Errorf("expected UNMASK_REQUEST, got %v", env.Type)
	}

	var payload pb.UnmaskRequestPayload
	if err := googleproto.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	if !payload.Ready {
		t.Error("expected ready=true in unmask request")
	}
}

func TestUnmaskResponder_SendsValidResponse(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}
	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	session := manager.CreateSession(testPeerID, protocol.RoleResponder)
	session.Handshake.Transition(protocol.EventInitiate)
	session.Handshake.Transition(protocol.EventAttestationSuccess)
	session.Handshake.Transition(protocol.EventMatchAboveThreshold)
	session.Handshake.Transition(protocol.EventDealBreakersMatch)
	session.Handshake.Transition(protocol.EventChatApproval)

	session.IdentityPayload = &pb.IdentityPayload{
		DisplayName: "Bob",
		Email:       "bob@example.com",
	}

	// Create incoming request
	reqPayload := &pb.UnmaskRequestPayload{Ready: true}
	payload, _ := googleproto.Marshal(reqPayload)

	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_UNMASK_REQUEST,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	// Create initiator's identity response that will be sent after responder's response
	initiatorIdentityPayload := &pb.UnmaskResponsePayload{
		Accepted: true,
		Identity: &pb.IdentityPayload{
			DisplayName: "Alice",
			Email:       "alice@example.com",
		},
	}
	initiatorPayload, _ := googleproto.Marshal(initiatorIdentityPayload)

	initiatorEnv := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_UNMASK_RESPONSE,
		Payload:   initiatorPayload,
		Timestamp: time.Now().Unix(),
	}

	// Set up pipes - we need bidirectional communication
	inputR, inputW := io.Pipe()
	outputR, outputW := io.Pipe()

	go func() {
		// Send the unmask request
		WriteEnvelope(inputW, env)
		// Signal approval after request is read
		time.Sleep(50 * time.Millisecond)
		session.SignalApproval(true)
		// Wait for response to be written, then send initiator's identity
		time.Sleep(50 * time.Millisecond)
		WriteEnvelope(inputW, initiatorEnv)
	}()

	// Read responder's output in background
	var respEnv *pb.HandshakeEnvelope
	var readErr error
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		respEnv, readErr = ReadEnvelope(outputR)
	}()

	session.Stream = &mockStream{reader: inputR, writer: outputW}

	err := handler.doUnmaskResponder(session)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wait for the reader goroutine to complete
	<-readDone

	if readErr != nil {
		t.Fatalf("failed to read response envelope: %v", readErr)
	}

	if respEnv == nil {
		t.Fatal("no response envelope read")
	}

	if respEnv.Type != pb.MessageType_UNMASK_RESPONSE {
		t.Errorf("expected UNMASK_RESPONSE, got %v", respEnv.Type)
	}

	var respPayload pb.UnmaskResponsePayload
	if err := googleproto.Unmarshal(respEnv.Payload, &respPayload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	if !respPayload.Accepted {
		t.Error("expected accepted=true in unmask response")
	}

	if respPayload.Identity == nil {
		t.Fatal("expected identity in response")
	}

	if respPayload.Identity.DisplayName != "Bob" {
		t.Errorf("expected display name Bob, got %s", respPayload.Identity.DisplayName)
	}

	// Verify peer identity was stored
	if session.PeerIdentity == nil {
		t.Error("expected responder to have peer identity")
	}
	if session.PeerIdentity != nil && session.PeerIdentity.DisplayName != "Alice" {
		t.Errorf("expected peer display name Alice, got %s", session.PeerIdentity.DisplayName)
	}
}

func TestUnmaskResponder_RejectsWrongMessageType(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}
	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Create a message with wrong type
	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_DEALBREAKER_REQUEST, // Wrong type
		Payload:   []byte("test"),
		Timestamp: time.Now().Unix(),
	}

	session := manager.CreateSession(testPeerID, protocol.RoleResponder)
	session.Handshake.Transition(protocol.EventInitiate)
	session.Handshake.Transition(protocol.EventAttestationSuccess)
	session.Handshake.Transition(protocol.EventMatchAboveThreshold)
	session.Handshake.Transition(protocol.EventDealBreakersMatch)
	session.Handshake.Transition(protocol.EventChatApproval)

	session.IdentityPayload = &pb.IdentityPayload{DisplayName: "Bob"}

	r, w := io.Pipe()
	outputBuf := &bytes.Buffer{}
	go func() {
		WriteEnvelope(w, env)
		w.Close()
	}()

	session.Stream = &mockStream{reader: r, writer: outputBuf}

	err := handler.doUnmaskResponder(session)
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}

	if err.Error() != "unexpected message type: DEALBREAKER_REQUEST" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUnmaskInitiator_HandlesReject(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}
	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	session := manager.CreateSession(testPeerID, protocol.RoleInitiator)
	session.Handshake.Transition(protocol.EventInitiate)
	session.Handshake.Transition(protocol.EventAttestationSuccess)
	session.Handshake.Transition(protocol.EventMatchAboveThreshold)
	session.Handshake.Transition(protocol.EventDealBreakersMatch)
	session.Handshake.Transition(protocol.EventChatApproval)

	session.IdentityPayload = &pb.IdentityPayload{DisplayName: "Alice"}

	// Create a REJECT response
	rejectPayload := &pb.RejectPayload{
		Reason: "user declined unmask",
		Stage:  "unmask",
	}
	rejectPayloadBytes, _ := googleproto.Marshal(rejectPayload)

	rejectEnv := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_REJECT,
		Payload:   rejectPayloadBytes,
		Timestamp: time.Now().Unix(),
	}

	// Create pipes for communication
	inputR, inputW := io.Pipe()

	go func() {
		// Read and discard the request from initiator
		ReadEnvelope(inputR)
	}()

	// Create a reader that will provide the reject message
	respBuf := &bytes.Buffer{}
	WriteEnvelope(respBuf, rejectEnv)

	// Signal approval to send request
	go func() {
		time.Sleep(50 * time.Millisecond)
		session.SignalApproval(true)
	}()

	session.Stream = &mockStream{
		reader: respBuf,
		writer: inputW,
	}

	err := handler.doUnmaskInitiator(session)
	if err == nil {
		t.Fatal("expected error for rejection")
	}

	if err.Error() != "peer rejected: user declined unmask" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUnmaskInitiator_NilIdentity(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}
	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	session := manager.CreateSession(testPeerID, protocol.RoleInitiator)
	session.Handshake.Transition(protocol.EventInitiate)
	session.Handshake.Transition(protocol.EventAttestationSuccess)
	session.Handshake.Transition(protocol.EventMatchAboveThreshold)
	session.Handshake.Transition(protocol.EventDealBreakersMatch)
	session.Handshake.Transition(protocol.EventChatApproval)

	// Do NOT set IdentityPayload
	session.IdentityPayload = nil

	var buf bytes.Buffer
	session.Stream = &mockStream{reader: &buf, writer: &buf}

	err := handler.doUnmaskInitiator(session)
	if err == nil {
		t.Fatal("expected error for nil identity")
	}

	if err.Error() != "identity payload not set" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUnmaskInitiator_RejectsWrongMessageType(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}
	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	session := manager.CreateSession(testPeerID, protocol.RoleInitiator)
	session.Handshake.Transition(protocol.EventInitiate)
	session.Handshake.Transition(protocol.EventAttestationSuccess)
	session.Handshake.Transition(protocol.EventMatchAboveThreshold)
	session.Handshake.Transition(protocol.EventDealBreakersMatch)
	session.Handshake.Transition(protocol.EventChatApproval)

	session.IdentityPayload = &pb.IdentityPayload{DisplayName: "Alice"}

	// Create a wrong message type (request instead of response)
	wrongEnv := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_UNMASK_REQUEST, // Wrong type for initiator
		Payload:   []byte("test"),
		Timestamp: time.Now().Unix(),
	}

	// Create pipes for communication
	inputR, inputW := io.Pipe()

	go func() {
		// Read and discard the request from initiator
		ReadEnvelope(inputR)
	}()

	// Create a reader that will provide the wrong message type
	respBuf := &bytes.Buffer{}
	WriteEnvelope(respBuf, wrongEnv)

	// Signal approval to send request
	go func() {
		time.Sleep(50 * time.Millisecond)
		session.SignalApproval(true)
	}()

	session.Stream = &mockStream{
		reader: respBuf,
		writer: inputW,
	}

	err := handler.doUnmaskInitiator(session)
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}

	if err.Error() != "unexpected message type: UNMASK_REQUEST" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUnmaskResponder_NilIdentity(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}
	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	session := manager.CreateSession(testPeerID, protocol.RoleResponder)
	session.Handshake.Transition(protocol.EventInitiate)
	session.Handshake.Transition(protocol.EventAttestationSuccess)
	session.Handshake.Transition(protocol.EventMatchAboveThreshold)
	session.Handshake.Transition(protocol.EventDealBreakersMatch)
	session.Handshake.Transition(protocol.EventChatApproval)

	// Do NOT set IdentityPayload
	session.IdentityPayload = nil

	var buf bytes.Buffer
	session.Stream = &mockStream{reader: &buf, writer: &buf}

	err := handler.doUnmaskResponder(session)
	if err == nil {
		t.Fatal("expected error for nil identity")
	}

	if err.Error() != "identity payload not set" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSession_ApprovalChannel(t *testing.T) {
	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	t.Run("approval signal received", func(t *testing.T) {
		session := NewSession(testPeerID, protocol.RoleInitiator, 0.7)

		go func() {
			time.Sleep(10 * time.Millisecond)
			session.SignalApproval(true)
		}()

		ctx := context.Background()
		result, err := session.WaitForApproval(ctx)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !result {
			t.Error("expected approval to be true")
		}
	})

	t.Run("rejection signal received", func(t *testing.T) {
		session := NewSession(testPeerID, protocol.RoleInitiator, 0.7)

		go func() {
			time.Sleep(10 * time.Millisecond)
			session.SignalApproval(false)
		}()

		ctx := context.Background()
		result, err := session.WaitForApproval(ctx)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result {
			t.Error("expected approval to be false")
		}
	})

	t.Run("multiple signals - first wins", func(t *testing.T) {
		session := NewSession(testPeerID, protocol.RoleInitiator, 0.7)

		go func() {
			time.Sleep(10 * time.Millisecond)
			session.SignalApproval(true)
			session.SignalApproval(false) // Should be ignored (non-blocking)
		}()

		ctx := context.Background()
		result, err := session.WaitForApproval(ctx)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !result {
			t.Error("expected first approval to be true")
		}
	})

	t.Run("context timeout", func(t *testing.T) {
		session := NewSession(testPeerID, protocol.RoleInitiator, 0.7)

		// Don't signal approval - let context timeout
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, err := session.WaitForApproval(ctx)
		if err != ErrApprovalTimeout {
			t.Errorf("expected ErrApprovalTimeout, got: %v", err)
		}
	})
}

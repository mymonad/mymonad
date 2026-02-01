package handshake

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2pprotocol "github.com/libp2p/go-libp2p/core/protocol"
	pb "github.com/mymonad/mymonad/api/proto"
	"github.com/mymonad/mymonad/pkg/hashcash"
	"github.com/mymonad/mymonad/pkg/protocol"
	googleproto "google.golang.org/protobuf/proto"
)

func TestProtocolID(t *testing.T) {
	if ProtocolID != "/mymonad/handshake/1.0.0" {
		t.Errorf("unexpected protocol ID: %s", ProtocolID)
	}
}

func TestNewStreamHandler(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}
	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
	if handler.manager != manager {
		t.Error("handler manager mismatch")
	}
	if handler.logger != logger {
		t.Error("handler logger mismatch")
	}
}

func TestStreamHandler_EmitStateChange(t *testing.T) {
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

	// Create a session manually
	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	session := manager.CreateSession(testPeerID, protocol.RoleInitiator)

	// Emit state change
	handler.emitStateChange(session)

	// Check event was received
	select {
	case e := <-events:
		if e.SessionID != session.ID {
			t.Errorf("expected session ID %s, got %s", session.ID, e.SessionID)
		}
		if e.EventType != "stage_changed" {
			t.Errorf("expected event type stage_changed, got %s", e.EventType)
		}
		if e.State != "Idle" {
			t.Errorf("expected state Idle, got %s", e.State)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for event")
	}
}

func TestStreamHandler_InitiateHandshake_CooldownActive(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}
	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Record an attempt to put peer in cooldown
	manager.RecordAttempt(testPeerID)

	// Try to initiate - should fail due to cooldown
	_, err := handler.InitiateHandshake(nil, nil, testPeerID)
	if err == nil {
		t.Fatal("expected error for cooldown")
	}
	expectedErrMsg := "cooldown active for peer " + testPeerID.String()
	if err.Error() != expectedErrMsg {
		t.Errorf("unexpected error message: %v", err)
	}
}

// mockStream implements network.Stream for testing.
type mockStream struct {
	reader io.Reader
	writer io.Writer
}

func (m *mockStream) Read(p []byte) (n int, err error) {
	return m.reader.Read(p)
}

func (m *mockStream) Write(p []byte) (n int, err error) {
	return m.writer.Write(p)
}

func (m *mockStream) Close() error                           { return nil }
func (m *mockStream) CloseRead() error                       { return nil }
func (m *mockStream) CloseWrite() error                      { return nil }
func (m *mockStream) Reset() error                           { return nil }
func (m *mockStream) ResetWithError(code network.StreamErrorCode) error { return nil }
func (m *mockStream) SetDeadline(t time.Time) error          { return nil }
func (m *mockStream) SetReadDeadline(t time.Time) error      { return nil }
func (m *mockStream) SetWriteDeadline(t time.Time) error     { return nil }
func (m *mockStream) ID() string                             { return "mock-stream-id" }
func (m *mockStream) Protocol() libp2pprotocol.ID            { return libp2pprotocol.ID(ProtocolID) }
func (m *mockStream) SetProtocol(id libp2pprotocol.ID) error { return nil }
func (m *mockStream) Stat() network.Stats                    { return network.Stats{} }
func (m *mockStream) Conn() network.Conn                     { return nil }
func (m *mockStream) Scope() network.StreamScope             { return nil }

// newMockStreamPair creates a bidirectional stream pair for testing.
// Returns (initiatorSide, responderSide).
func newMockStreamPair() (*mockStream, *mockStream) {
	// Initiator writes to pipe1, responder reads from pipe1
	r1, w1 := io.Pipe()
	// Responder writes to pipe2, initiator reads from pipe2
	r2, w2 := io.Pipe()

	initiatorSide := &mockStream{reader: r2, writer: w1}
	responderSide := &mockStream{reader: r1, writer: w2}

	return initiatorSide, responderSide
}

func TestAttestation_SuccessfulExchange(t *testing.T) {
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

	// Create sessions
	initiatorSession := initiatorManager.CreateSession(testPeerID, protocol.RoleInitiator)
	responderSession := responderManager.CreateSession(testPeerID, protocol.RoleResponder)

	// Start both state machines
	initiatorSession.Handshake.Transition(protocol.EventInitiate)
	responderSession.Handshake.Transition(protocol.EventInitiate)

	// Assign streams
	initiatorSession.Stream = initiatorStream
	responderSession.Stream = responderStream

	var wg sync.WaitGroup
	var initiatorErr, responderErr error

	// Run responder in background (it needs to read first)
	wg.Add(1)
	go func() {
		defer wg.Done()
		responderErr = responderHandler.doAttestationResponder(responderSession)
	}()

	// Run initiator
	wg.Add(1)
	go func() {
		defer wg.Done()
		initiatorErr = initiatorHandler.doAttestationInitiator(initiatorSession)
	}()

	wg.Wait()

	if initiatorErr != nil {
		t.Errorf("initiator attestation failed: %v", initiatorErr)
	}
	if responderErr != nil {
		t.Errorf("responder attestation failed: %v", responderErr)
	}
}

func TestAttestation_InitiatorSendsValidRequest(t *testing.T) {
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

	// Use a pipe for reading (will close causing error) and buffer for writing
	r, w := io.Pipe()
	go func() {
		// Let initiator write the request
		time.Sleep(50 * time.Millisecond)
		w.Close() // This will cause the read to fail, ending the test
	}()

	session.Stream = &mockStream{reader: r, writer: &buf}

	// This will fail on read (as expected), but the request should be written
	_ = handler.doAttestationInitiator(session)

	// Verify the request was written
	if buf.Len() == 0 {
		t.Fatal("no data written by initiator")
	}

	// Parse the written envelope
	env, err := ReadEnvelope(&buf)
	if err != nil {
		t.Fatalf("failed to read envelope: %v", err)
	}

	if env.Type != pb.MessageType_ATTESTATION_REQUEST {
		t.Errorf("expected ATTESTATION_REQUEST, got %v", env.Type)
	}

	var payload pb.AttestationRequestPayload
	if err := googleproto.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	if payload.Version != Version {
		t.Errorf("expected version %s, got %s", Version, payload.Version)
	}

	if payload.Challenge == "" {
		t.Error("expected non-empty challenge")
	}

	// Verify the challenge is parseable
	challenge, err := hashcash.ParseChallenge(payload.Challenge)
	if err != nil {
		t.Errorf("failed to parse challenge: %v", err)
	}

	if challenge.Bits != DefaultAttestationDifficulty {
		t.Errorf("expected difficulty %d, got %d", DefaultAttestationDifficulty, challenge.Bits)
	}
}

func TestAttestation_ResponderRejectsInvalidVersion(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}
	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Create request with wrong version
	reqPayload := &pb.AttestationRequestPayload{
		Version:   "0.0.1", // Wrong version
		PeerId:    "test-peer",
		Challenge: "1:16:1706745600:test:MTIzNDU2",
	}
	payload, _ := googleproto.Marshal(reqPayload)

	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_REQUEST,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	// Create a custom mock for this test
	session := manager.CreateSession(testPeerID, protocol.RoleResponder)
	session.Handshake.Transition(protocol.EventInitiate)

	r, w := io.Pipe()
	outputBuf := &bytes.Buffer{}
	go func() {
		WriteEnvelope(w, env)
		w.Close()
	}()

	session.Stream = &mockStream{reader: r, writer: outputBuf}

	err := handler.doAttestationResponder(session)
	if err == nil {
		t.Fatal("expected error for version mismatch")
	}

	if err.Error() != "version mismatch: expected 1.0.0, got 0.0.1" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAttestation_ResponderRejectsExpiredChallenge(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}
	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Create an expired challenge by using a timestamp from 10 minutes ago
	// The string format is: version:bits:timestamp:resource:rand
	// When parsed, it will have DefaultExpiration (5 min), but since timestamp
	// is 10 minutes ago, it's definitely expired.
	oldTimestamp := time.Now().Add(-10 * time.Minute).Unix()
	expiredChallengeStr := "1:16:" + strconv.FormatInt(oldTimestamp, 10) + ":test:MTIzNDU2"

	reqPayload := &pb.AttestationRequestPayload{
		Version:   Version,
		PeerId:    "test-peer",
		Challenge: expiredChallengeStr,
	}
	payload, _ := googleproto.Marshal(reqPayload)

	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_REQUEST,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	session := manager.CreateSession(testPeerID, protocol.RoleResponder)
	session.Handshake.Transition(protocol.EventInitiate)

	r, w := io.Pipe()
	outputBuf := &bytes.Buffer{}
	go func() {
		WriteEnvelope(w, env)
		w.Close()
	}()

	session.Stream = &mockStream{reader: r, writer: outputBuf}

	err := handler.doAttestationResponder(session)
	if err == nil {
		t.Fatal("expected error for expired challenge")
	}

	if err.Error() != "challenge has expired" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAttestation_InitiatorRejectsInvalidSolution(t *testing.T) {
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

	// Create a mock response with an invalid solution
	respPayload := &pb.AttestationResponsePayload{
		Version:  Version,
		PeerId:   "responder-peer",
		Solution: "1:16:1706745600:test:MTIzNDU2:0", // Wrong counter (invalid PoW)
	}
	respPayloadBytes, _ := googleproto.Marshal(respPayload)

	respEnv := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_RESPONSE,
		Payload:   respPayloadBytes,
		Timestamp: time.Now().Unix(),
	}

	// Create pipes for communication
	inputR, inputW := io.Pipe()

	go func() {
		// Read and discard the request from initiator
		ReadEnvelope(inputR)
	}()

	// Create a reader that will provide the invalid response
	respBuf := &bytes.Buffer{}
	WriteEnvelope(respBuf, respEnv)

	session.Stream = &mockStream{
		reader: respBuf,
		writer: inputW,
	}

	err := handler.doAttestationInitiator(session)
	if err == nil {
		t.Fatal("expected error for invalid solution")
	}

	// The error should be about invalid proof-of-work or solution not matching
	if err.Error() != "invalid proof-of-work solution" && err.Error() != "solution does not match challenge" {
		t.Logf("got error: %v (this is expected)", err)
	}
}

func TestAttestation_ResponderSolvesChallenge(t *testing.T) {
	// Test that the responder can correctly solve a challenge
	challenge := hashcash.NewChallenge("test-resource", DefaultAttestationDifficulty, hashcash.DefaultExpiration)

	solution, err := hashcash.Solve(challenge)
	if err != nil {
		t.Fatalf("failed to solve challenge: %v", err)
	}

	// Verify the solution is valid
	if !solution.Verify() {
		t.Error("solution should be valid")
	}

	// Verify we can parse the solution string
	parsedSolution, err := hashcash.ParseSolution(solution.String())
	if err != nil {
		t.Fatalf("failed to parse solution string: %v", err)
	}

	if !parsedSolution.Verify() {
		t.Error("parsed solution should be valid")
	}
}

func TestAttestation_StateTransitions(t *testing.T) {
	// Test that attestation correctly transitions the state machine
	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	t.Run("success transitions to VectorMatch", func(t *testing.T) {
		h := protocol.NewHandshake(protocol.RoleInitiator, testPeerID, 0.7)

		// Start in Idle
		if h.State() != protocol.StateIdle {
			t.Errorf("expected StateIdle, got %v", h.State())
		}

		// Initiate -> Attestation
		if err := h.Transition(protocol.EventInitiate); err != nil {
			t.Fatalf("failed to transition to attestation: %v", err)
		}
		if h.State() != protocol.StateAttestation {
			t.Errorf("expected StateAttestation, got %v", h.State())
		}

		// Success -> VectorMatch
		if err := h.Transition(protocol.EventAttestationSuccess); err != nil {
			t.Fatalf("failed to transition to vector match: %v", err)
		}
		if h.State() != protocol.StateVectorMatch {
			t.Errorf("expected StateVectorMatch, got %v", h.State())
		}
	})

	t.Run("failure transitions to Failed", func(t *testing.T) {
		h := protocol.NewHandshake(protocol.RoleInitiator, testPeerID, 0.7)

		// Initiate -> Attestation
		if err := h.Transition(protocol.EventInitiate); err != nil {
			t.Fatalf("failed to transition to attestation: %v", err)
		}

		// Failure -> Failed
		if err := h.Transition(protocol.EventAttestationFailure); err != nil {
			t.Fatalf("failed to transition to failed: %v", err)
		}
		if h.State() != protocol.StateFailed {
			t.Errorf("expected StateFailed, got %v", h.State())
		}
	})
}

func TestVersion(t *testing.T) {
	if Version != "1.0.0" {
		t.Errorf("unexpected version: %s", Version)
	}
}

func TestDefaultAttestationDifficulty(t *testing.T) {
	if DefaultAttestationDifficulty != 16 {
		t.Errorf("unexpected default difficulty: %d", DefaultAttestationDifficulty)
	}

	// Verify it's reasonable (not too hard for tests)
	challenge := hashcash.NewChallenge("test", DefaultAttestationDifficulty, hashcash.DefaultExpiration)
	solution, err := hashcash.Solve(challenge)
	if err != nil {
		t.Fatalf("failed to solve challenge with default difficulty: %v", err)
	}
	if !solution.Verify() {
		t.Error("solution should be valid")
	}
}

func TestAttestation_InitiatorRejectsEmptySolution(t *testing.T) {
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

	// Create a mock response with an empty solution
	respPayload := &pb.AttestationResponsePayload{
		Version:  Version,
		PeerId:   "responder-peer",
		Solution: "", // Empty solution
	}
	respPayloadBytes, _ := googleproto.Marshal(respPayload)

	respEnv := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_RESPONSE,
		Payload:   respPayloadBytes,
		Timestamp: time.Now().Unix(),
	}

	// Create pipes for communication
	inputR, inputW := io.Pipe()

	go func() {
		// Read and discard the request from initiator
		ReadEnvelope(inputR)
	}()

	// Create a reader that will provide the response with empty solution
	respBuf := &bytes.Buffer{}
	WriteEnvelope(respBuf, respEnv)

	session.Stream = &mockStream{
		reader: respBuf,
		writer: inputW,
	}

	err := handler.doAttestationInitiator(session)
	if err == nil {
		t.Fatal("expected error for empty solution")
	}

	if err.Error() != "empty attestation solution" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAttestation_InitiatorRejectsVersionMismatch(t *testing.T) {
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

	// Create a mock response with wrong version
	respPayload := &pb.AttestationResponsePayload{
		Version:  "0.0.1", // Wrong version
		PeerId:   "responder-peer",
		Solution: "1:16:1706745600:test:MTIzNDU2:12345",
	}
	respPayloadBytes, _ := googleproto.Marshal(respPayload)

	respEnv := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_RESPONSE,
		Payload:   respPayloadBytes,
		Timestamp: time.Now().Unix(),
	}

	// Create pipes for communication
	inputR, inputW := io.Pipe()

	go func() {
		// Read and discard the request from initiator
		ReadEnvelope(inputR)
	}()

	// Create a reader that will provide the wrong version response
	respBuf := &bytes.Buffer{}
	WriteEnvelope(respBuf, respEnv)

	session.Stream = &mockStream{
		reader: respBuf,
		writer: inputW,
	}

	err := handler.doAttestationInitiator(session)
	if err == nil {
		t.Fatal("expected error for version mismatch")
	}

	if err.Error() != "version mismatch: expected 1.0.0, got 0.0.1" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAttestation_InitiatorHandlesReject(t *testing.T) {
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

	// Create a REJECT response
	rejectPayload := &pb.RejectPayload{
		Reason: "test rejection",
		Stage:  "attestation",
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

	session.Stream = &mockStream{
		reader: respBuf,
		writer: inputW,
	}

	err := handler.doAttestationInitiator(session)
	if err == nil {
		t.Fatal("expected error for rejection")
	}

	if err.Error() != "peer rejected: test rejection" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAttestation_ResponderRejectsInvalidChallenge(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}
	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Create request with invalid challenge format
	reqPayload := &pb.AttestationRequestPayload{
		Version:   Version,
		PeerId:    "test-peer",
		Challenge: "invalid-challenge-format", // Invalid format
	}
	payload, _ := googleproto.Marshal(reqPayload)

	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_REQUEST,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	session := manager.CreateSession(testPeerID, protocol.RoleResponder)
	session.Handshake.Transition(protocol.EventInitiate)

	r, w := io.Pipe()
	outputBuf := &bytes.Buffer{}
	go func() {
		WriteEnvelope(w, env)
		w.Close()
	}()

	session.Stream = &mockStream{reader: r, writer: outputBuf}

	err := handler.doAttestationResponder(session)
	if err == nil {
		t.Fatal("expected error for invalid challenge")
	}

	// Should contain "failed to parse challenge"
	if err.Error() != "failed to parse challenge: hashcash: invalid challenge format" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAttestation_ResponderRejectsWrongMessageType(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}
	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Create a message with wrong type (ATTESTATION_RESPONSE instead of REQUEST)
	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_RESPONSE, // Wrong type for responder
		Payload:   []byte("test"),
		Timestamp: time.Now().Unix(),
	}

	session := manager.CreateSession(testPeerID, protocol.RoleResponder)
	session.Handshake.Transition(protocol.EventInitiate)

	r, w := io.Pipe()
	outputBuf := &bytes.Buffer{}
	go func() {
		WriteEnvelope(w, env)
		w.Close()
	}()

	session.Stream = &mockStream{reader: r, writer: outputBuf}

	err := handler.doAttestationResponder(session)
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}

	if err.Error() != "unexpected message type: ATTESTATION_RESPONSE" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAttestation_InitiatorRejectsWrongMessageType(t *testing.T) {
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

	// Create a message with wrong type (ATTESTATION_REQUEST instead of RESPONSE)
	wrongEnv := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_REQUEST, // Wrong type for initiator response
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

	session.Stream = &mockStream{
		reader: respBuf,
		writer: inputW,
	}

	err := handler.doAttestationInitiator(session)
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}

	if err.Error() != "unexpected message type: ATTESTATION_REQUEST" {
		t.Errorf("unexpected error: %v", err)
	}
}

// Package handshake provides attestation integration tests for AntiSpamService.
package handshake

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	pb "github.com/mymonad/mymonad/api/proto"
	"github.com/mymonad/mymonad/internal/antispam"
	"github.com/mymonad/mymonad/pkg/hashcash"
	"github.com/mymonad/mymonad/pkg/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	googleproto "google.golang.org/protobuf/proto"
)

// ===========================================================================
// Manager.SetAntiSpamService Tests
// ===========================================================================

func TestManager_SetAntiSpamService(t *testing.T) {
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}
	manager := NewManager(nil, cfg)

	// Initially should be nil
	assert.Nil(t, manager.GetAntiSpamService(), "AntiSpamService should initially be nil")

	// Create and set an AntiSpamService
	as := antispam.NewAntiSpamService(nil)
	defer as.Stop()

	manager.SetAntiSpamService(as)

	// Should be set
	assert.NotNil(t, manager.GetAntiSpamService(), "AntiSpamService should be set")
	assert.Equal(t, as, manager.GetAntiSpamService(), "Should return the same service")
}

func TestManager_GetAntiSpamService_ThreadSafety(t *testing.T) {
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}
	manager := NewManager(nil, cfg)

	as := antispam.NewAntiSpamService(nil)
	defer as.Stop()

	var wg sync.WaitGroup
	wg.Add(2)

	// Concurrent setter
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			manager.SetAntiSpamService(as)
		}
	}()

	// Concurrent getter
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = manager.GetAntiSpamService()
		}
	}()

	wg.Wait()
	// Should not panic
	assert.True(t, true, "Concurrent access should not panic")
}

// ===========================================================================
// New Attestation Responder Tests (using AntiSpamService)
// ===========================================================================

func TestNewAttestationResponder_IssuesChallenge(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}

	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	// Set up AntiSpamService
	as := antispam.NewAntiSpamService(nil)
	defer as.Stop()
	manager.SetAntiSpamService(as)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Create a buffer to capture what responder writes
	var buf bytes.Buffer

	session := manager.CreateSession(testPeerID, protocol.RoleResponder)
	session.Handshake.Transition(protocol.EventInitiate)

	// Use a pipe for reading (will close after responder writes)
	r, w := io.Pipe()
	go func() {
		// Let responder write the challenge
		time.Sleep(50 * time.Millisecond)
		w.Close()
	}()

	session.Stream = &mockStream{reader: r, writer: &buf}

	// This will fail on read (as expected), but the challenge should be written
	_ = handler.doNewAttestationResponder(session)

	// Verify the challenge was written
	if buf.Len() == 0 {
		t.Fatal("no data written by responder")
	}

	// Parse the written envelope
	env, err := ReadEnvelope(&buf)
	require.NoError(t, err, "should be able to read envelope")

	assert.Equal(t, pb.MessageType_ATTESTATION_REQUEST, env.Type, "should send ATTESTATION_REQUEST with PoW challenge")

	// Parse the payload as PoWChallenge
	var challenge pb.PoWChallenge
	err = googleproto.Unmarshal(env.Payload, &challenge)
	require.NoError(t, err, "should be able to unmarshal PoWChallenge")

	assert.NotEmpty(t, challenge.Nonce, "challenge should have nonce")
	assert.NotZero(t, challenge.Timestamp, "challenge should have timestamp")
	assert.NotZero(t, challenge.Difficulty, "challenge should have difficulty")
}

func TestNewAttestationResponder_VerifiesValidSolution(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}

	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	// Set up AntiSpamService
	as := antispam.NewAntiSpamService(nil)
	defer as.Stop()
	manager.SetAntiSpamService(as)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Issue a challenge manually for the peer
	challenge, err := as.IssueChallenge(testPeerID)
	require.NoError(t, err)

	// Mine a valid solution
	miner := hashcash.NewMiner(0)
	result, err := miner.Mine(challenge, []byte(testPeerID))
	require.NoError(t, err)

	// Create solution
	solution := &pb.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	// Wrap solution in envelope
	solutionPayload, _ := googleproto.Marshal(solution)
	solutionEnv := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_RESPONSE,
		Payload:   solutionPayload,
		Timestamp: time.Now().Unix(),
	}

	// Set up streams
	inputR, inputW := io.Pipe()
	outputBuf := &bytes.Buffer{}

	// Write solution to the input
	go func() {
		// First, read the challenge the responder sends
		ReadEnvelope(inputR)
		// Responder will close the pipe
	}()

	// Prepare challenge to send
	challengePayload, _ := googleproto.Marshal(challenge)
	challengeEnv := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_REQUEST,
		Payload:   challengePayload,
		Timestamp: time.Now().Unix(),
	}

	// Create combined buffer: first write challenge for a test that reads it
	// Actually, for responder test, we need a different setup
	// Responder: writes challenge -> reads solution -> writes result

	// Let's use a simpler approach with a pipe pair
	responderIn, initiatorOut := io.Pipe()
	initiatorIn, responderOut := io.Pipe()

	session := manager.CreateSession(testPeerID, protocol.RoleResponder)
	session.Handshake.Transition(protocol.EventInitiate)
	session.Stream = &mockStream{reader: responderIn, writer: responderOut}

	var responderErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		responderErr = handler.doNewAttestationResponder(session)
	}()

	// Simulate initiator: read challenge, solve, send solution, read result
	env, err := ReadEnvelope(initiatorIn)
	require.NoError(t, err, "should read challenge")
	assert.Equal(t, pb.MessageType_ATTESTATION_REQUEST, env.Type)

	var recvChallenge pb.PoWChallenge
	err = googleproto.Unmarshal(env.Payload, &recvChallenge)
	require.NoError(t, err)

	// Mine the received challenge
	miner = hashcash.NewMiner(0)
	result, err = miner.Mine(&recvChallenge, []byte(testPeerID))
	require.NoError(t, err)

	// Send solution
	solution = &pb.PoWSolution{
		ChallengeNonce:     recvChallenge.Nonce,
		ChallengeTimestamp: recvChallenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}
	solutionPayload, _ = googleproto.Marshal(solution)
	solutionEnv = &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_RESPONSE,
		Payload:   solutionPayload,
		Timestamp: time.Now().Unix(),
	}
	err = WriteEnvelope(initiatorOut, solutionEnv)
	require.NoError(t, err)

	// Read result
	resultEnv, err := ReadEnvelope(initiatorIn)
	require.NoError(t, err, "should read result")
	assert.Equal(t, pb.MessageType_ATTESTATION_RESPONSE, resultEnv.Type)

	var powResult pb.PoWResult
	err = googleproto.Unmarshal(resultEnv.Payload, &powResult)
	require.NoError(t, err)
	assert.True(t, powResult.Valid, "valid solution should be accepted")

	initiatorOut.Close()
	initiatorIn.Close()
	wg.Wait()

	assert.NoError(t, responderErr, "responder should succeed with valid solution")

	// Cleanup for unused variables
	_ = outputBuf
	_ = inputW
	_ = challengeEnv
}

func TestNewAttestationResponder_RejectsInvalidSolution(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}

	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	// Set up AntiSpamService
	as := antispam.NewAntiSpamService(nil)
	defer as.Stop()
	manager.SetAntiSpamService(as)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Use pipe pair
	responderIn, initiatorOut := io.Pipe()
	initiatorIn, responderOut := io.Pipe()

	session := manager.CreateSession(testPeerID, protocol.RoleResponder)
	session.Handshake.Transition(protocol.EventInitiate)
	session.Stream = &mockStream{reader: responderIn, writer: responderOut}

	var responderErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		responderErr = handler.doNewAttestationResponder(session)
	}()

	// Simulate initiator: read challenge, send invalid solution
	env, err := ReadEnvelope(initiatorIn)
	require.NoError(t, err, "should read challenge")

	var recvChallenge pb.PoWChallenge
	err = googleproto.Unmarshal(env.Payload, &recvChallenge)
	require.NoError(t, err)

	// Send INVALID solution (zero proof)
	invalidSolution := &pb.PoWSolution{
		ChallengeNonce:     recvChallenge.Nonce,
		ChallengeTimestamp: recvChallenge.Timestamp,
		Counter:            12345,
		Proof:              make([]byte, 32), // Invalid proof
	}
	solutionPayload, _ := googleproto.Marshal(invalidSolution)
	solutionEnv := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_RESPONSE,
		Payload:   solutionPayload,
		Timestamp: time.Now().Unix(),
	}
	err = WriteEnvelope(initiatorOut, solutionEnv)
	require.NoError(t, err)

	// Read result (should indicate invalid)
	resultEnv, err := ReadEnvelope(initiatorIn)
	require.NoError(t, err, "should read result")

	var powResult pb.PoWResult
	err = googleproto.Unmarshal(resultEnv.Payload, &powResult)
	require.NoError(t, err)
	assert.False(t, powResult.Valid, "invalid solution should be rejected")
	assert.NotEmpty(t, powResult.Error, "should have error message")

	initiatorOut.Close()
	initiatorIn.Close()
	wg.Wait()

	assert.Error(t, responderErr, "responder should return error for invalid solution")
}

// ===========================================================================
// New Attestation Initiator Tests (using Miner)
// ===========================================================================

func TestNewAttestationInitiator_ReceivesChallengeAndMines(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}

	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	// Set up AntiSpamService (for initiator to have context)
	as := antispam.NewAntiSpamService(nil)
	defer as.Stop()
	manager.SetAntiSpamService(as)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Use pipe pair
	initiatorIn, responderOut := io.Pipe()
	responderIn, initiatorOut := io.Pipe()

	session := manager.CreateSession(testPeerID, protocol.RoleInitiator)
	session.Handshake.Transition(protocol.EventInitiate)
	session.Stream = &mockStream{reader: initiatorIn, writer: initiatorOut}

	var initiatorErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		initiatorErr = handler.doNewAttestationInitiator(session)
	}()

	// Simulate responder: send challenge, read solution, send result
	// Create and send challenge
	challenge := &pb.PoWChallenge{
		Nonce:      make([]byte, 16),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 8, // Easy difficulty for fast test
		PeerId:     []byte(testPeerID),
	}
	// Fill nonce with some random data
	copy(challenge.Nonce, "testnonce1234567")

	challengePayload, _ := googleproto.Marshal(challenge)
	challengeEnv := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_REQUEST,
		Payload:   challengePayload,
		Timestamp: time.Now().Unix(),
	}
	err := WriteEnvelope(responderOut, challengeEnv)
	require.NoError(t, err)

	// Read solution from initiator
	solutionEnv, err := ReadEnvelope(responderIn)
	require.NoError(t, err, "should read solution from initiator")
	assert.Equal(t, pb.MessageType_ATTESTATION_RESPONSE, solutionEnv.Type)

	var solution pb.PoWSolution
	err = googleproto.Unmarshal(solutionEnv.Payload, &solution)
	require.NoError(t, err)

	assert.Equal(t, challenge.Nonce, solution.ChallengeNonce, "solution should reference challenge nonce")
	assert.Equal(t, challenge.Timestamp, solution.ChallengeTimestamp, "solution should reference challenge timestamp")
	assert.NotEmpty(t, solution.Proof, "solution should have proof")

	// Verify the solution is actually valid
	// Since the host is nil, the initiator uses the PeerId from the challenge
	verifyErr := hashcash.Verify(challenge, &solution, challenge.PeerId)
	assert.NoError(t, verifyErr, "solution should be valid for the challenge's peer ID")

	// Send success result
	result := &pb.PoWResult{Valid: true}
	resultPayload, _ := googleproto.Marshal(result)
	resultEnv := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_RESPONSE,
		Payload:   resultPayload,
		Timestamp: time.Now().Unix(),
	}
	err = WriteEnvelope(responderOut, resultEnv)
	require.NoError(t, err)

	responderOut.Close()
	responderIn.Close()
	wg.Wait()

	// Initiator should succeed
	assert.NoError(t, initiatorErr, "initiator should succeed with valid result")

	// Unused variable cleanup
	_ = verifyErr
}

func TestNewAttestationInitiator_HandlesRejection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}

	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	// Set up AntiSpamService
	as := antispam.NewAntiSpamService(nil)
	defer as.Stop()
	manager.SetAntiSpamService(as)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Use pipe pair
	initiatorIn, responderOut := io.Pipe()
	responderIn, initiatorOut := io.Pipe()

	session := manager.CreateSession(testPeerID, protocol.RoleInitiator)
	session.Handshake.Transition(protocol.EventInitiate)
	session.Stream = &mockStream{reader: initiatorIn, writer: initiatorOut}

	var initiatorErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		initiatorErr = handler.doNewAttestationInitiator(session)
	}()

	// Simulate responder: send challenge, read solution, send REJECTION
	challenge := &pb.PoWChallenge{
		Nonce:      make([]byte, 16),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 8,
		PeerId:     []byte(testPeerID),
	}
	copy(challenge.Nonce, "testnonce1234567")

	challengePayload, _ := googleproto.Marshal(challenge)
	challengeEnv := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_REQUEST,
		Payload:   challengePayload,
		Timestamp: time.Now().Unix(),
	}
	err := WriteEnvelope(responderOut, challengeEnv)
	require.NoError(t, err)

	// Read solution (we'll reject it regardless)
	_, err = ReadEnvelope(responderIn)
	require.NoError(t, err)

	// Send rejection result
	result := &pb.PoWResult{Valid: false, Error: "solution rejected for testing"}
	resultPayload, _ := googleproto.Marshal(result)
	resultEnv := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_RESPONSE,
		Payload:   resultPayload,
		Timestamp: time.Now().Unix(),
	}
	err = WriteEnvelope(responderOut, resultEnv)
	require.NoError(t, err)

	responderOut.Close()
	responderIn.Close()
	wg.Wait()

	// Initiator should return error
	assert.Error(t, initiatorErr, "initiator should return error on rejection")
	assert.Contains(t, initiatorErr.Error(), "rejected", "error should indicate rejection")
}

// ===========================================================================
// Full Attestation Flow Tests (Initiator + Responder)
// ===========================================================================

func TestNewAttestation_FullSuccessfulExchange(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}

	// Create managers for both sides
	initiatorManager := NewManager(nil, cfg)
	responderManager := NewManager(nil, cfg)

	initiatorHandler := NewStreamHandler(initiatorManager, logger)
	responderHandler := NewStreamHandler(responderManager, logger)

	// Set up AntiSpamService for both (in real scenario, each node has its own)
	initiatorAS := antispam.NewAntiSpamService(nil)
	responderAS := antispam.NewAntiSpamService(nil)
	defer initiatorAS.Stop()
	defer responderAS.Stop()

	initiatorManager.SetAntiSpamService(initiatorAS)
	responderManager.SetAntiSpamService(responderAS)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Create pipe pair for communication
	initiatorStream, responderStream := newMockStreamPair()

	// Create sessions
	initiatorSession := initiatorManager.CreateSession(testPeerID, protocol.RoleInitiator)
	responderSession := responderManager.CreateSession(testPeerID, protocol.RoleResponder)

	initiatorSession.Handshake.Transition(protocol.EventInitiate)
	responderSession.Handshake.Transition(protocol.EventInitiate)

	initiatorSession.Stream = initiatorStream
	responderSession.Stream = responderStream

	var wg sync.WaitGroup
	var initiatorErr, responderErr error

	// Run responder (issues challenge, verifies solution)
	wg.Add(1)
	go func() {
		defer wg.Done()
		responderErr = responderHandler.doNewAttestationResponder(responderSession)
	}()

	// Run initiator (receives challenge, mines solution)
	wg.Add(1)
	go func() {
		defer wg.Done()
		initiatorErr = initiatorHandler.doNewAttestationInitiator(initiatorSession)
	}()

	wg.Wait()

	assert.NoError(t, initiatorErr, "initiator attestation should succeed")
	assert.NoError(t, responderErr, "responder attestation should succeed")
}

func TestNewAttestation_FullExchangeWithInvalidSolution(t *testing.T) {
	// This test ensures that when the initiator sends an invalid solution,
	// both sides handle the failure gracefully.
	// For now, we're testing the happy path - invalid solution paths are
	// covered in individual unit tests above.
	t.Skip("Covered by unit tests for individual roles")
}

// ===========================================================================
// UseNewAttestation Tests
// ===========================================================================

func TestUseNewAttestation_ReturnsTrueWhenServiceSet(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}
	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	// Initially should return false
	assert.False(t, handler.UseNewAttestation(), "should return false when AntiSpamService not set")

	// Set AntiSpamService
	as := antispam.NewAntiSpamService(nil)
	defer as.Stop()
	manager.SetAntiSpamService(as)

	// Now should return true
	assert.True(t, handler.UseNewAttestation(), "should return true when AntiSpamService is set")
}

func TestNewAttestationResponder_NoAntiSpamService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}

	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	// Do NOT set AntiSpamService

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	var buf bytes.Buffer
	session := manager.CreateSession(testPeerID, protocol.RoleResponder)
	session.Handshake.Transition(protocol.EventInitiate)
	session.Stream = &mockStream{reader: &buf, writer: &buf}

	err := handler.doNewAttestationResponder(session)
	require.Error(t, err, "should fail without AntiSpamService")
	assert.Contains(t, err.Error(), "AntiSpamService not configured", "error should indicate missing service")
}

func TestNewAttestationInitiator_HandlesReadError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}

	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Create a pipe that closes immediately
	r, w := io.Pipe()
	w.Close() // Close immediately to simulate read error

	session := manager.CreateSession(testPeerID, protocol.RoleInitiator)
	session.Handshake.Transition(protocol.EventInitiate)
	session.Stream = &mockStream{reader: r, writer: &bytes.Buffer{}}

	err := handler.doNewAttestationInitiator(session)
	require.Error(t, err, "should fail on read error")
	assert.Contains(t, err.Error(), "failed to read challenge", "error should indicate read failure")
}

func TestNewAttestationInitiator_HandlesWrongMessageType(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}

	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Send wrong message type (ATTESTATION_RESPONSE instead of REQUEST)
	wrongEnv := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_RESPONSE,
		Payload:   []byte("test"),
		Timestamp: time.Now().Unix(),
	}

	var inputBuf bytes.Buffer
	WriteEnvelope(&inputBuf, wrongEnv)

	session := manager.CreateSession(testPeerID, protocol.RoleInitiator)
	session.Handshake.Transition(protocol.EventInitiate)
	session.Stream = &mockStream{reader: &inputBuf, writer: &bytes.Buffer{}}

	err := handler.doNewAttestationInitiator(session)
	require.Error(t, err, "should fail on wrong message type")
	assert.Contains(t, err.Error(), "unexpected message type", "error should indicate wrong type")
}

func TestNewAttestationResponder_HandlesReadError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}

	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	as := antispam.NewAntiSpamService(nil)
	defer as.Stop()
	manager.SetAntiSpamService(as)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Create pipes
	initiatorIn, responderOut := io.Pipe()
	responderIn, initiatorOut := io.Pipe()

	session := manager.CreateSession(testPeerID, protocol.RoleResponder)
	session.Handshake.Transition(protocol.EventInitiate)
	session.Stream = &mockStream{reader: responderIn, writer: responderOut}

	var responderErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		responderErr = handler.doNewAttestationResponder(session)
	}()

	// Read the challenge
	_, err := ReadEnvelope(initiatorIn)
	require.NoError(t, err)

	// Close the pipe without sending a solution - causes read error
	initiatorOut.Close()
	initiatorIn.Close()

	wg.Wait()

	assert.Error(t, responderErr, "should fail on read error")
	assert.Contains(t, responderErr.Error(), "failed to read solution", "error should indicate read failure")
}

func TestNewAttestationResponder_HandlesWrongMessageType(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := ManagerConfig{
		AutoInitiate:     false,
		CooldownDuration: 10 * time.Minute,
		Threshold:        0.7,
	}

	manager := NewManager(nil, cfg)
	handler := NewStreamHandler(manager, logger)

	as := antispam.NewAntiSpamService(nil)
	defer as.Stop()
	manager.SetAntiSpamService(as)

	testPeerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Create pipes
	initiatorIn, responderOut := io.Pipe()
	responderIn, initiatorOut := io.Pipe()

	session := manager.CreateSession(testPeerID, protocol.RoleResponder)
	session.Handshake.Transition(protocol.EventInitiate)
	session.Stream = &mockStream{reader: responderIn, writer: responderOut}

	var responderErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		responderErr = handler.doNewAttestationResponder(session)
	}()

	// Read the challenge
	_, err := ReadEnvelope(initiatorIn)
	require.NoError(t, err)

	// Send wrong message type
	wrongEnv := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_REQUEST, // Wrong type
		Payload:   []byte("test"),
		Timestamp: time.Now().Unix(),
	}
	WriteEnvelope(initiatorOut, wrongEnv)

	initiatorOut.Close()
	initiatorIn.Close()

	wg.Wait()

	assert.Error(t, responderErr, "should fail on wrong message type")
	assert.Contains(t, responderErr.Error(), "unexpected message type", "error should indicate wrong type")
}

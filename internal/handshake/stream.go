// Package handshake provides stream handling for the handshake protocol.
package handshake

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	pb "github.com/mymonad/mymonad/api/proto"
	"github.com/mymonad/mymonad/pkg/hashcash"
	proto "github.com/mymonad/mymonad/pkg/protocol"
	googleproto "google.golang.org/protobuf/proto"
)

// ProtocolID is the libp2p protocol identifier for handshakes.
const ProtocolID = "/mymonad/handshake/1.0.0"

// Version is the current protocol version string.
const Version = "1.0.0"

// DefaultAttestationDifficulty is the default PoW difficulty for attestation.
// 16 bits = ~65k iterations, fast enough for tests but still meaningful.
const DefaultAttestationDifficulty = 16

// StreamHandler handles incoming handshake streams.
type StreamHandler struct {
	manager *Manager
	logger  *slog.Logger
}

// NewStreamHandler creates a new stream handler.
func NewStreamHandler(manager *Manager, logger *slog.Logger) *StreamHandler {
	return &StreamHandler{
		manager: manager,
		logger:  logger,
	}
}

// Register registers the stream handler with the host.
func (h *StreamHandler) Register(host host.Host) {
	host.SetStreamHandler(protocol.ID(ProtocolID), h.handleStream)
}

// handleStream handles an incoming handshake stream.
func (h *StreamHandler) handleStream(s network.Stream) {
	peerID := s.Conn().RemotePeer()
	h.logger.Info("incoming handshake stream", "peer", peerID.String())

	// Check if we can accept this handshake
	if !h.manager.CanInitiate(peerID) {
		h.logger.Warn("rejecting handshake, cooldown active", "peer", peerID.String())
		h.sendReject(s, "cooldown active")
		s.Close()
		return
	}

	// Create session as responder
	session := h.manager.CreateSession(peerID, proto.RoleResponder)
	session.Stream = s

	h.manager.EmitEvent(Event{
		SessionID: session.ID,
		EventType: "started",
		State:     session.State().String(),
		PeerID:    peerID.String(),
	})

	// Start the protocol handler
	go h.runProtocol(session)
}

// InitiateHandshake starts a handshake with a peer.
func (h *StreamHandler) InitiateHandshake(ctx context.Context, host host.Host, peerID peer.ID) (*Session, error) {
	// Check cooldown
	if !h.manager.CanInitiate(peerID) {
		return nil, fmt.Errorf("cooldown active for peer %s", peerID.String())
	}

	// Open stream
	s, err := host.NewStream(ctx, peerID, protocol.ID(ProtocolID))
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}

	// Create session as initiator
	session := h.manager.CreateSession(peerID, proto.RoleInitiator)
	session.Stream = s

	h.manager.EmitEvent(Event{
		SessionID: session.ID,
		EventType: "started",
		State:     session.State().String(),
		PeerID:    peerID.String(),
	})

	// Start the protocol handler
	go h.runProtocol(session)

	return session, nil
}

// runProtocol runs the handshake protocol for a session.
func (h *StreamHandler) runProtocol(session *Session) {
	defer func() {
		h.manager.RemoveSession(session.ID)
	}()

	// Start state machine
	if err := session.Handshake.Transition(proto.EventInitiate); err != nil {
		h.logger.Error("failed to start handshake", "error", err)
		return
	}

	h.emitStateChange(session)

	// Protocol loop based on role
	if session.Role == proto.RoleInitiator {
		h.runInitiator(session)
	} else {
		h.runResponder(session)
	}
}

// runInitiator runs the initiator side of the protocol.
func (h *StreamHandler) runInitiator(session *Session) {
	// Stage 1: Attestation
	if err := h.doAttestationInitiator(session); err != nil {
		h.logger.Error("attestation failed", "error", err)
		session.Handshake.Transition(proto.EventAttestationFailure)
		h.manager.EmitEvent(Event{
			SessionID: session.ID,
			EventType: "failed",
			State:     session.State().String(),
			PeerID:    session.PeerID.String(),
		})
		return
	}
	session.Handshake.Transition(proto.EventAttestationSuccess)
	h.emitStateChange(session)

	// TODO: Continue to vector match in Task 13
	h.logger.Info("initiator attestation complete", "session", session.ID)
}

// runResponder runs the responder side of the protocol.
func (h *StreamHandler) runResponder(session *Session) {
	// Stage 1: Attestation
	if err := h.doAttestationResponder(session); err != nil {
		h.logger.Error("attestation failed", "error", err)
		session.Handshake.Transition(proto.EventAttestationFailure)
		h.manager.EmitEvent(Event{
			SessionID: session.ID,
			EventType: "failed",
			State:     session.State().String(),
			PeerID:    session.PeerID.String(),
		})
		return
	}
	session.Handshake.Transition(proto.EventAttestationSuccess)
	h.emitStateChange(session)

	// TODO: Continue to vector match in Task 13
	h.logger.Info("responder attestation complete", "session", session.ID)
}

// sendReject sends a reject message and closes the stream.
func (h *StreamHandler) sendReject(s network.Stream, reason string) {
	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_REJECT,
		Payload:   []byte(reason),
		Timestamp: time.Now().Unix(),
	}
	WriteEnvelope(s, env)
}

// emitStateChange emits a state change event.
func (h *StreamHandler) emitStateChange(session *Session) {
	h.manager.EmitEvent(Event{
		SessionID:      session.ID,
		EventType:      "stage_changed",
		State:          session.State().String(),
		PeerID:         session.PeerID.String(),
		ElapsedSeconds: session.ElapsedSeconds(),
	})
}

// doAttestationInitiator performs the initiator side of attestation.
// The initiator sends a hashcash challenge and verifies the response.
func (h *StreamHandler) doAttestationInitiator(session *Session) error {
	// Get our peer ID
	var myPeerID string
	if h.manager.host != nil {
		myPeerID = h.manager.host.ID().String()
	} else {
		myPeerID = "unknown"
	}

	// Create hashcash challenge targeting the responder's peer ID
	challenge := hashcash.NewChallenge(
		session.PeerID.String(),
		DefaultAttestationDifficulty,
		hashcash.DefaultExpiration,
	)

	// Create attestation request payload
	reqPayload := &pb.AttestationRequestPayload{
		Version:   Version,
		PeerId:    myPeerID,
		Challenge: challenge.String(),
	}

	payload, err := googleproto.Marshal(reqPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal request payload: %w", err)
	}

	// Send request
	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_REQUEST,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	h.logger.Debug("sending attestation request",
		"session", session.ID,
		"challenge", challenge.String(),
	)

	if err := WriteEnvelope(session.Stream, env); err != nil {
		return fmt.Errorf("failed to send attestation request: %w", err)
	}

	session.UpdateActivity()

	// Read response
	respEnv, err := ReadEnvelope(session.Stream)
	if err != nil {
		return fmt.Errorf("failed to read attestation response: %w", err)
	}

	session.UpdateActivity()

	// Handle rejection
	if respEnv.Type == pb.MessageType_REJECT {
		var rejectPayload pb.RejectPayload
		if err := googleproto.Unmarshal(respEnv.Payload, &rejectPayload); err != nil {
			return fmt.Errorf("peer rejected (unable to parse reason)")
		}
		return fmt.Errorf("peer rejected: %s", rejectPayload.Reason)
	}

	// Verify message type
	if respEnv.Type != pb.MessageType_ATTESTATION_RESPONSE {
		return fmt.Errorf("unexpected message type: %v", respEnv.Type)
	}

	// Parse response payload
	var respPayload pb.AttestationResponsePayload
	if err := googleproto.Unmarshal(respEnv.Payload, &respPayload); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Verify version compatibility
	if respPayload.Version != Version {
		return fmt.Errorf("version mismatch: expected %s, got %s", Version, respPayload.Version)
	}

	// Verify the solution
	if respPayload.Solution == "" {
		return fmt.Errorf("empty attestation solution")
	}

	// Parse and verify the hashcash solution
	solution, err := hashcash.ParseSolution(respPayload.Solution)
	if err != nil {
		return fmt.Errorf("failed to parse solution: %w", err)
	}

	// Verify the solution is valid (hash has required leading zeros)
	if !solution.Verify() {
		return fmt.Errorf("invalid proof-of-work solution")
	}

	// Verify the solution is for our challenge
	if solution.Challenge.String() != challenge.String() {
		return fmt.Errorf("solution does not match challenge")
	}

	h.logger.Debug("attestation verified",
		"session", session.ID,
		"peer", respPayload.PeerId,
		"solution_counter", solution.Counter,
	)

	return nil
}

// doAttestationResponder performs the responder side of attestation.
// The responder receives a hashcash challenge, solves it, and sends the solution.
func (h *StreamHandler) doAttestationResponder(session *Session) error {
	// Read request
	reqEnv, err := ReadEnvelope(session.Stream)
	if err != nil {
		return fmt.Errorf("failed to read attestation request: %w", err)
	}

	session.UpdateActivity()

	// Verify message type
	if reqEnv.Type != pb.MessageType_ATTESTATION_REQUEST {
		return fmt.Errorf("unexpected message type: %v", reqEnv.Type)
	}

	// Parse request payload
	var reqPayload pb.AttestationRequestPayload
	if err := googleproto.Unmarshal(reqEnv.Payload, &reqPayload); err != nil {
		return fmt.Errorf("failed to unmarshal request: %w", err)
	}

	h.logger.Debug("received attestation request",
		"session", session.ID,
		"peer", reqPayload.PeerId,
		"challenge", reqPayload.Challenge,
	)

	// Verify version compatibility
	if reqPayload.Version != Version {
		h.sendRejectWithReason(session.Stream, "version mismatch", "attestation")
		return fmt.Errorf("version mismatch: expected %s, got %s", Version, reqPayload.Version)
	}

	// Parse the challenge
	challenge, err := hashcash.ParseChallenge(reqPayload.Challenge)
	if err != nil {
		h.sendRejectWithReason(session.Stream, "invalid challenge format", "attestation")
		return fmt.Errorf("failed to parse challenge: %w", err)
	}

	// Check if challenge has expired
	if challenge.IsExpired() {
		h.sendRejectWithReason(session.Stream, "challenge expired", "attestation")
		return fmt.Errorf("challenge has expired")
	}

	// Solve the challenge
	solution, err := hashcash.Solve(challenge)
	if err != nil {
		h.sendRejectWithReason(session.Stream, "failed to solve challenge", "attestation")
		return fmt.Errorf("failed to solve challenge: %w", err)
	}

	// Get our peer ID
	var myPeerID string
	if h.manager.host != nil {
		myPeerID = h.manager.host.ID().String()
	} else {
		myPeerID = "unknown"
	}

	// Create response payload
	respPayload := &pb.AttestationResponsePayload{
		Version:  Version,
		PeerId:   myPeerID,
		Solution: solution.String(),
	}

	payload, err := googleproto.Marshal(respPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal response payload: %w", err)
	}

	// Send response
	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_RESPONSE,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	h.logger.Debug("sending attestation response",
		"session", session.ID,
		"solution_counter", solution.Counter,
	)

	if err := WriteEnvelope(session.Stream, env); err != nil {
		return fmt.Errorf("failed to send attestation response: %w", err)
	}

	session.UpdateActivity()

	return nil
}

// sendRejectWithReason sends a REJECT message with a structured payload.
func (h *StreamHandler) sendRejectWithReason(s network.Stream, reason, stage string) {
	rejectPayload := &pb.RejectPayload{
		Reason: reason,
		Stage:  stage,
	}
	payload, err := googleproto.Marshal(rejectPayload)
	if err != nil {
		// Fall back to simple reject
		h.sendReject(s, reason)
		return
	}

	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_REJECT,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}
	WriteEnvelope(s, env)
}

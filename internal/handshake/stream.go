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
	"github.com/mymonad/mymonad/internal/tee"
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
	session.SetStream(s)

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
	session.SetStream(s)

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
		h.transition(session, proto.EventAttestationFailure)
		h.manager.EmitEvent(Event{
			SessionID: session.ID,
			EventType: "failed",
			State:     session.State().String(),
			PeerID:    session.PeerID.String(),
		})
		return
	}
	h.transition(session, proto.EventAttestationSuccess)
	h.emitStateChange(session)
	h.logger.Info("initiator attestation complete", "session", session.ID)

	// Stage 2: Vector Match
	if err := h.doVectorMatchInitiator(session); err != nil {
		h.logger.Error("vector match failed", "error", err)
		h.transition(session, proto.EventMatchBelowThreshold)
		h.manager.EmitEvent(Event{
			SessionID: session.ID,
			EventType: "failed",
			State:     session.State().String(),
			PeerID:    session.PeerID.String(),
		})
		return
	}
	h.transition(session, proto.EventMatchAboveThreshold)
	h.emitStateChange(session)
	h.logger.Info("initiator vector match complete", "session", session.ID)

	// Stage 3: Deal Breakers
	if err := h.doDealBreakersInitiator(session); err != nil {
		h.logger.Error("deal breakers failed", "error", err)
		h.transition(session, proto.EventDealBreakersMismatch)
		h.manager.EmitEvent(Event{
			SessionID: session.ID,
			EventType: "failed",
			State:     session.State().String(),
			PeerID:    session.PeerID.String(),
		})
		return
	}
	h.transition(session, proto.EventDealBreakersMatch)
	h.emitStateChange(session)
	h.logger.Info("initiator deal breakers complete", "session", session.ID)

	// Skip HumanChat (synthetic chat) for now - go directly to Unmask
	// In production, there would be an EventChatApproval transition here after chat
	h.transition(session, proto.EventChatApproval) // Skip to Unmask state
	h.emitStateChange(session)

	// Stage 5: Unmask
	if err := h.doUnmaskInitiator(session); err != nil {
		h.logger.Error("unmask failed", "error", err)
		h.transition(session, proto.EventUnmaskRejection)
		h.manager.EmitEvent(Event{
			SessionID: session.ID,
			EventType: "failed",
			State:     session.State().String(),
			PeerID:    session.PeerID.String(),
		})
		return
	}
	h.transition(session, proto.EventMutualApproval)
	h.emitStateChange(session)
	h.logger.Info("initiator unmask complete", "session", session.ID)

	// Emit completed event
	h.manager.EmitEvent(Event{
		SessionID: session.ID,
		EventType: "completed",
		State:     session.State().String(),
		PeerID:    session.PeerID.String(),
	})
}

// runResponder runs the responder side of the protocol.
func (h *StreamHandler) runResponder(session *Session) {
	// Stage 1: Attestation
	if err := h.doAttestationResponder(session); err != nil {
		h.logger.Error("attestation failed", "error", err)
		h.transition(session, proto.EventAttestationFailure)
		h.manager.EmitEvent(Event{
			SessionID: session.ID,
			EventType: "failed",
			State:     session.State().String(),
			PeerID:    session.PeerID.String(),
		})
		return
	}
	h.transition(session, proto.EventAttestationSuccess)
	h.emitStateChange(session)
	h.logger.Info("responder attestation complete", "session", session.ID)

	// Stage 2: Vector Match
	if err := h.doVectorMatchResponder(session); err != nil {
		h.logger.Error("vector match failed", "error", err)
		h.transition(session, proto.EventMatchBelowThreshold)
		h.manager.EmitEvent(Event{
			SessionID: session.ID,
			EventType: "failed",
			State:     session.State().String(),
			PeerID:    session.PeerID.String(),
		})
		return
	}
	h.transition(session, proto.EventMatchAboveThreshold)
	h.emitStateChange(session)
	h.logger.Info("responder vector match complete", "session", session.ID)

	// Stage 3: Deal Breakers
	if err := h.doDealBreakersResponder(session); err != nil {
		h.logger.Error("deal breakers failed", "error", err)
		h.transition(session, proto.EventDealBreakersMismatch)
		h.manager.EmitEvent(Event{
			SessionID: session.ID,
			EventType: "failed",
			State:     session.State().String(),
			PeerID:    session.PeerID.String(),
		})
		return
	}
	h.transition(session, proto.EventDealBreakersMatch)
	h.emitStateChange(session)
	h.logger.Info("responder deal breakers complete", "session", session.ID)

	// Skip HumanChat (synthetic chat) for now - go directly to Unmask
	// In production, there would be an EventChatApproval transition here after chat
	h.transition(session, proto.EventChatApproval) // Skip to Unmask state
	h.emitStateChange(session)

	// Stage 5: Unmask
	if err := h.doUnmaskResponder(session); err != nil {
		h.logger.Error("unmask failed", "error", err)
		h.transition(session, proto.EventUnmaskRejection)
		h.manager.EmitEvent(Event{
			SessionID: session.ID,
			EventType: "failed",
			State:     session.State().String(),
			PeerID:    session.PeerID.String(),
		})
		return
	}
	h.transition(session, proto.EventMutualApproval)
	h.emitStateChange(session)
	h.logger.Info("responder unmask complete", "session", session.ID)

	// Emit completed event
	h.manager.EmitEvent(Event{
		SessionID: session.ID,
		EventType: "completed",
		State:     session.State().String(),
		PeerID:    session.PeerID.String(),
	})
}

// sendReject sends a reject message and closes the stream.
func (h *StreamHandler) sendReject(s network.Stream, reason string) {
	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_REJECT,
		Payload:   []byte(reason),
		Timestamp: time.Now().Unix(),
	}
	if err := WriteEnvelope(s, env); err != nil {
		h.logger.Warn("failed to send reject message", "error", err, "reason", reason)
	}
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

// transition performs a state transition and logs any errors.
// This is a helper to ensure transition errors are never silently ignored.
func (h *StreamHandler) transition(session *Session, event proto.Event) {
	if err := session.Handshake.Transition(event); err != nil {
		h.logger.Error("state transition failed",
			"session", session.ID,
			"event", event.String(),
			"current_state", session.State().String(),
			"error", err,
		)
	}
}

// doAttestationInitiator performs the initiator side of attestation.
// The initiator sends a hashcash challenge and verifies the response.
func (h *StreamHandler) doAttestationInitiator(session *Session) error {
	// Get thread-safe copy of session stream
	stream := session.GetStream()

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

	if err := WriteEnvelope(stream, env); err != nil {
		return fmt.Errorf("failed to send attestation request: %w", err)
	}

	session.UpdateActivity()

	// Read response
	respEnv, err := ReadEnvelope(stream)
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
	// Get thread-safe copy of session stream
	stream := session.GetStream()

	// Read request
	reqEnv, err := ReadEnvelope(stream)
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
		h.sendRejectWithReason(stream, "version mismatch", "attestation")
		return fmt.Errorf("version mismatch: expected %s, got %s", Version, reqPayload.Version)
	}

	// Parse the challenge
	challenge, err := hashcash.ParseChallenge(reqPayload.Challenge)
	if err != nil {
		h.sendRejectWithReason(stream, "invalid challenge format", "attestation")
		return fmt.Errorf("failed to parse challenge: %w", err)
	}

	// Check if challenge has expired
	if challenge.IsExpired() {
		h.sendRejectWithReason(stream, "challenge expired", "attestation")
		return fmt.Errorf("challenge has expired")
	}

	// Solve the challenge
	solution, err := hashcash.Solve(challenge)
	if err != nil {
		h.sendRejectWithReason(stream, "failed to solve challenge", "attestation")
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

	if err := WriteEnvelope(stream, env); err != nil {
		return fmt.Errorf("failed to send attestation response: %w", err)
	}

	session.UpdateActivity()

	return nil
}

// ===========================================================================
// Vector Match Stage
// ===========================================================================

// doVectorMatchInitiator performs the initiator side of vector match.
// The initiator sends their encrypted monad and receives match result.
func (h *StreamHandler) doVectorMatchInitiator(session *Session) error {
	// Get thread-safe copies of session data
	localMonad := session.GetLocalMonad()
	stream := session.GetStream()

	// Verify we have our monad
	if len(localMonad) == 0 {
		return fmt.Errorf("local monad not set")
	}

	// Get our peer ID
	var myPeerID string
	if h.manager.host != nil {
		myPeerID = h.manager.host.ID().String()
	} else {
		myPeerID = "unknown"
	}

	// Create vector match request payload
	reqPayload := &pb.VectorMatchRequestPayload{
		PeerId:         myPeerID,
		EncryptedMonad: localMonad, // In production, this would be encrypted
	}

	payload, err := googleproto.Marshal(reqPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal request payload: %w", err)
	}

	// Send request
	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_VECTOR_MATCH_REQUEST,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	h.logger.Debug("sending vector match request",
		"session", session.ID,
		"monad_size", len(localMonad),
	)

	if err := WriteEnvelope(stream, env); err != nil {
		return fmt.Errorf("failed to send vector match request: %w", err)
	}

	session.UpdateActivity()

	// Read response
	respEnv, err := ReadEnvelope(stream)
	if err != nil {
		return fmt.Errorf("failed to read vector match response: %w", err)
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
	if respEnv.Type != pb.MessageType_VECTOR_MATCH_RESPONSE {
		return fmt.Errorf("unexpected message type: %v", respEnv.Type)
	}

	// Parse response payload
	var respPayload pb.VectorMatchResponsePayload
	if err := googleproto.Unmarshal(respEnv.Payload, &respPayload); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	h.logger.Debug("received vector match response",
		"session", session.ID,
		"peer", respPayload.PeerId,
		"matched", respPayload.Matched,
	)

	// Check if we matched
	if !respPayload.Matched {
		return fmt.Errorf("vector match failed: below threshold")
	}

	return nil
}

// doVectorMatchResponder performs the responder side of vector match.
// The responder receives peer monad, computes similarity, and sends result.
func (h *StreamHandler) doVectorMatchResponder(session *Session) error {
	// Get thread-safe copies of session data
	localMonad := session.GetLocalMonad()
	stream := session.GetStream()

	// Verify we have our monad
	if len(localMonad) == 0 {
		return fmt.Errorf("local monad not set")
	}

	// Read request
	reqEnv, err := ReadEnvelope(stream)
	if err != nil {
		return fmt.Errorf("failed to read vector match request: %w", err)
	}

	session.UpdateActivity()

	// Verify message type
	if reqEnv.Type != pb.MessageType_VECTOR_MATCH_REQUEST {
		return fmt.Errorf("unexpected message type: %v", reqEnv.Type)
	}

	// Parse request payload
	var reqPayload pb.VectorMatchRequestPayload
	if err := googleproto.Unmarshal(reqEnv.Payload, &reqPayload); err != nil {
		return fmt.Errorf("failed to unmarshal request: %w", err)
	}

	h.logger.Debug("received vector match request",
		"session", session.ID,
		"peer", reqPayload.PeerId,
		"monad_size", len(reqPayload.EncryptedMonad),
	)

	// Store peer's monad for later use (will be cleaned up when session ends)
	session.SetPeerMonad(reqPayload.EncryptedMonad)
	peerMonad := reqPayload.EncryptedMonad

	// Get threshold from the handshake (which got it from manager config)
	threshold := session.Handshake.Threshold()

	// Compute match using MockTEE
	// In production, this would run inside SGX
	matched, err := tee.ComputeMatch(localMonad, peerMonad, threshold)
	if err != nil {
		h.sendRejectWithReason(stream, "failed to compute match", "vector_match")
		return fmt.Errorf("failed to compute match: %w", err)
	}

	// Get our peer ID
	var myPeerID string
	if h.manager.host != nil {
		myPeerID = h.manager.host.ID().String()
	} else {
		myPeerID = "unknown"
	}

	// Create response payload
	// Note: We only reveal matched/not-matched, not the actual score
	respPayload := &pb.VectorMatchResponsePayload{
		PeerId:  myPeerID,
		Matched: matched,
	}

	payload, err := googleproto.Marshal(respPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal response payload: %w", err)
	}

	// Send response
	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_VECTOR_MATCH_RESPONSE,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	h.logger.Debug("sending vector match response",
		"session", session.ID,
		"matched", matched,
	)

	if err := WriteEnvelope(stream, env); err != nil {
		return fmt.Errorf("failed to send vector match response: %w", err)
	}

	session.UpdateActivity()

	// If not matched, return error so caller knows to fail
	if !matched {
		return fmt.Errorf("vector match failed: below threshold")
	}

	return nil
}

// ===========================================================================
// Deal Breakers Stage
// ===========================================================================

// doDealBreakersInitiator performs the initiator side of deal breakers.
// The initiator sends their questions+answers and receives peer's answers.
func (h *StreamHandler) doDealBreakersInitiator(session *Session) error {
	// Get thread-safe copies of session data
	dealBreakerConfig := session.GetDealBreakerConfig()
	stream := session.GetStream()

	// Verify deal breaker config is set
	if dealBreakerConfig == nil {
		return fmt.Errorf("deal breaker config not set")
	}

	// Create deal breaker request payload with our questions and answers
	questions := make([]*pb.DealBreakerQuestion, len(dealBreakerConfig.Questions))
	for i, q := range dealBreakerConfig.Questions {
		questions[i] = &pb.DealBreakerQuestion{
			Id:       q.ID,
			Question: q.Question,
			Answer:   q.MyAnswer,
		}
	}

	reqPayload := &pb.DealBreakerRequestPayload{
		Questions: questions,
	}

	payload, err := googleproto.Marshal(reqPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal request payload: %w", err)
	}

	// Send request
	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_DEALBREAKER_REQUEST,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	h.logger.Debug("sending deal breaker request",
		"session", session.ID,
		"questions", len(questions),
	)

	if err := WriteEnvelope(stream, env); err != nil {
		return fmt.Errorf("failed to send deal breaker request: %w", err)
	}

	session.UpdateActivity()

	// Read response
	respEnv, err := ReadEnvelope(stream)
	if err != nil {
		return fmt.Errorf("failed to read deal breaker response: %w", err)
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
	if respEnv.Type != pb.MessageType_DEALBREAKER_RESPONSE {
		return fmt.Errorf("unexpected message type: %v", respEnv.Type)
	}

	// Parse response payload
	var respPayload pb.DealBreakerResponsePayload
	if err := googleproto.Unmarshal(respEnv.Payload, &respPayload); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	h.logger.Debug("received deal breaker response",
		"session", session.ID,
		"answers", len(respPayload.Answers),
		"peer_compatible", respPayload.Compatible,
	)

	// If peer marked us as incompatible, fail
	if !respPayload.Compatible {
		return fmt.Errorf("deal breakers failed: incompatible")
	}

	// Check our compatibility with peer's answers
	peerAnswers := make(map[string]bool)
	for _, a := range respPayload.Answers {
		peerAnswers[a.QuestionId] = a.Answer
	}

	if !checkCompatibility(dealBreakerConfig.Questions, peerAnswers) {
		return fmt.Errorf("deal breakers failed: incompatible")
	}

	return nil
}

// doDealBreakersResponder performs the responder side of deal breakers.
// The responder receives peer's questions+answers and sends their own answers.
func (h *StreamHandler) doDealBreakersResponder(session *Session) error {
	// Get thread-safe copies of session data
	dealBreakerConfig := session.GetDealBreakerConfig()
	stream := session.GetStream()

	// Verify deal breaker config is set
	if dealBreakerConfig == nil {
		return fmt.Errorf("deal breaker config not set")
	}

	// Read request
	reqEnv, err := ReadEnvelope(stream)
	if err != nil {
		return fmt.Errorf("failed to read deal breaker request: %w", err)
	}

	session.UpdateActivity()

	// Verify message type
	if reqEnv.Type != pb.MessageType_DEALBREAKER_REQUEST {
		return fmt.Errorf("unexpected message type: %v", reqEnv.Type)
	}

	// Parse request payload
	var reqPayload pb.DealBreakerRequestPayload
	if err := googleproto.Unmarshal(reqEnv.Payload, &reqPayload); err != nil {
		return fmt.Errorf("failed to unmarshal request: %w", err)
	}

	h.logger.Debug("received deal breaker request",
		"session", session.ID,
		"questions", len(reqPayload.Questions),
	)

	// Build peer's answers map from the request
	peerAnswers := make(map[string]bool)
	for _, q := range reqPayload.Questions {
		peerAnswers[q.Id] = q.Answer
	}

	// Check compatibility: do peer's answers meet our requirements?
	compatible := checkCompatibility(dealBreakerConfig.Questions, peerAnswers)

	// Create our answers to send back
	answers := make([]*pb.DealBreakerAnswer, len(dealBreakerConfig.Questions))
	for i, q := range dealBreakerConfig.Questions {
		answers[i] = &pb.DealBreakerAnswer{
			QuestionId: q.ID,
			Answer:     q.MyAnswer,
		}
	}

	// Create response payload
	respPayload := &pb.DealBreakerResponsePayload{
		Answers:    answers,
		Compatible: compatible,
	}

	payload, err := googleproto.Marshal(respPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal response payload: %w", err)
	}

	// Send response
	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_DEALBREAKER_RESPONSE,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	h.logger.Debug("sending deal breaker response",
		"session", session.ID,
		"answers", len(answers),
		"compatible", compatible,
	)

	if err := WriteEnvelope(stream, env); err != nil {
		return fmt.Errorf("failed to send deal breaker response: %w", err)
	}

	session.UpdateActivity()

	// If not compatible, return error so caller knows to fail
	if !compatible {
		return fmt.Errorf("deal breakers failed: incompatible")
	}

	return nil
}

// checkCompatibility checks if peer's answers meet our requirements.
// For each of our required questions, the peer must have provided a matching answer.
func checkCompatibility(ourQuestions []DealBreakerQuestion, peerAnswers map[string]bool) bool {
	for _, q := range ourQuestions {
		if !q.Required {
			continue // Skip non-required questions
		}

		peerAnswer, exists := peerAnswers[q.ID]
		if !exists {
			// Peer didn't answer this required question
			return false
		}

		if peerAnswer != q.MyAnswer {
			// Peer's answer doesn't match our requirement
			return false
		}
	}
	return true
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
	if err := WriteEnvelope(s, env); err != nil {
		h.logger.Warn("failed to send reject message", "error", err, "reason", reason, "stage", stage)
	}
}

// ===========================================================================
// Unmask Stage
// ===========================================================================

// doUnmaskInitiator performs the initiator side of unmask.
// The initiator waits for human approval, then sends UNMASK_REQUEST and receives UNMASK_RESPONSE.
func (h *StreamHandler) doUnmaskInitiator(session *Session) error {
	// Get thread-safe copies of session data
	identityPayload := session.GetIdentityPayload()
	stream := session.GetStream()

	// Verify identity payload is set
	if identityPayload == nil {
		return fmt.Errorf("identity payload not set")
	}

	// 1. Mark session as pending approval
	session.SetPendingApproval("unmask")
	h.manager.EmitEvent(Event{
		SessionID: session.ID,
		EventType: "pending_approval",
		State:     session.State().String(),
		PeerID:    session.PeerID.String(),
	})

	// 2. Wait for human approval (blocking, with timeout)
	// Use a reasonable timeout (e.g., 5 minutes) for human approval
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	approved, err := session.WaitForApproval(ctx)
	if err != nil {
		h.sendRejectWithReason(stream, "approval timeout", "unmask")
		return fmt.Errorf("approval timeout: %w", err)
	}
	if !approved {
		// Human rejected - send REJECT
		h.sendRejectWithReason(stream, "user rejected", "unmask")
		return fmt.Errorf("user rejected unmask")
	}

	session.ClearPendingApproval()

	// 3. Send UNMASK_REQUEST ready=true
	reqPayload := &pb.UnmaskRequestPayload{
		Ready: true,
	}

	payload, err := googleproto.Marshal(reqPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal request payload: %w", err)
	}

	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_UNMASK_REQUEST,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	h.logger.Debug("sending unmask request", "session", session.ID)

	if err := WriteEnvelope(stream, env); err != nil {
		return fmt.Errorf("failed to send unmask request: %w", err)
	}

	session.UpdateActivity()

	// 4. Read UNMASK_RESPONSE from peer
	respEnv, err := ReadEnvelope(stream)
	if err != nil {
		return fmt.Errorf("failed to read unmask response: %w", err)
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
	if respEnv.Type != pb.MessageType_UNMASK_RESPONSE {
		return fmt.Errorf("unexpected message type: %v", respEnv.Type)
	}

	// Parse response payload
	var respPayload pb.UnmaskResponsePayload
	if err := googleproto.Unmarshal(respEnv.Payload, &respPayload); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	h.logger.Debug("received unmask response",
		"session", session.ID,
		"accepted", respPayload.Accepted,
	)

	// 5. Check if peer accepted
	if !respPayload.Accepted {
		return fmt.Errorf("peer rejected unmask")
	}

	// 6. Store peer's identity
	session.SetPeerIdentity(respPayload.Identity)

	// 7. Send our identity back to peer (completing the bidirectional exchange)
	ourRespPayload := &pb.UnmaskResponsePayload{
		Accepted: true,
		Identity: identityPayload,
	}

	ourPayload, err := googleproto.Marshal(ourRespPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal our response payload: %w", err)
	}

	ourEnv := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_UNMASK_RESPONSE,
		Payload:   ourPayload,
		Timestamp: time.Now().Unix(),
	}

	h.logger.Debug("sending our unmask response", "session", session.ID)

	if err := WriteEnvelope(stream, ourEnv); err != nil {
		return fmt.Errorf("failed to send our unmask response: %w", err)
	}

	session.UpdateActivity()

	h.logger.Info("unmask complete",
		"session", session.ID,
		"peer_display_name", respPayload.Identity.GetDisplayName(),
	)

	return nil
}

// doUnmaskResponder performs the responder side of unmask.
// The responder reads UNMASK_REQUEST, waits for human approval, then sends UNMASK_RESPONSE.
func (h *StreamHandler) doUnmaskResponder(session *Session) error {
	// Get thread-safe copies of session data
	identityPayload := session.GetIdentityPayload()
	stream := session.GetStream()

	// Verify identity payload is set
	if identityPayload == nil {
		return fmt.Errorf("identity payload not set")
	}

	// 1. Read UNMASK_REQUEST from peer
	reqEnv, err := ReadEnvelope(stream)
	if err != nil {
		return fmt.Errorf("failed to read unmask request: %w", err)
	}

	session.UpdateActivity()

	// Handle rejection from peer
	if reqEnv.Type == pb.MessageType_REJECT {
		var rejectPayload pb.RejectPayload
		if err := googleproto.Unmarshal(reqEnv.Payload, &rejectPayload); err != nil {
			return fmt.Errorf("peer rejected (unable to parse reason)")
		}
		return fmt.Errorf("peer rejected: %s", rejectPayload.Reason)
	}

	// Verify message type
	if reqEnv.Type != pb.MessageType_UNMASK_REQUEST {
		return fmt.Errorf("unexpected message type: %v", reqEnv.Type)
	}

	// Parse request payload
	var reqPayload pb.UnmaskRequestPayload
	if err := googleproto.Unmarshal(reqEnv.Payload, &reqPayload); err != nil {
		return fmt.Errorf("failed to unmarshal request: %w", err)
	}

	h.logger.Debug("received unmask request",
		"session", session.ID,
		"ready", reqPayload.Ready,
	)

	// 2. Mark session as pending approval
	session.SetPendingApproval("unmask")
	h.manager.EmitEvent(Event{
		SessionID: session.ID,
		EventType: "pending_approval",
		State:     session.State().String(),
		PeerID:    session.PeerID.String(),
	})

	// 3. Wait for human approval (blocking, with timeout)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	approved, err := session.WaitForApproval(ctx)
	if err != nil {
		session.ClearPendingApproval()
		h.sendRejectWithReason(stream, "approval timeout", "unmask")
		return fmt.Errorf("approval timeout: %w", err)
	}
	session.ClearPendingApproval()

	// 4. Send UNMASK_RESPONSE
	var respPayload *pb.UnmaskResponsePayload
	if approved {
		respPayload = &pb.UnmaskResponsePayload{
			Accepted: true,
			Identity: identityPayload,
		}
	} else {
		respPayload = &pb.UnmaskResponsePayload{
			Accepted: false,
		}
	}

	payload, err := googleproto.Marshal(respPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal response payload: %w", err)
	}

	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_UNMASK_RESPONSE,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	h.logger.Debug("sending unmask response",
		"session", session.ID,
		"accepted", approved,
	)

	if err := WriteEnvelope(stream, env); err != nil {
		return fmt.Errorf("failed to send unmask response: %w", err)
	}

	session.UpdateActivity()

	// If not approved, return error
	if !approved {
		return fmt.Errorf("user rejected unmask")
	}

	// 5. Read initiator's identity response
	peerRespEnv, err := ReadEnvelope(stream)
	if err != nil {
		return fmt.Errorf("failed to read peer identity response: %w", err)
	}

	session.UpdateActivity()

	// Verify message type
	if peerRespEnv.Type != pb.MessageType_UNMASK_RESPONSE {
		return fmt.Errorf("unexpected message type for peer identity: %v", peerRespEnv.Type)
	}

	// Parse peer's identity
	var peerRespPayload pb.UnmaskResponsePayload
	if err := googleproto.Unmarshal(peerRespEnv.Payload, &peerRespPayload); err != nil {
		return fmt.Errorf("failed to unmarshal peer identity: %w", err)
	}

	h.logger.Debug("received peer identity",
		"session", session.ID,
		"accepted", peerRespPayload.Accepted,
	)

	// Store peer's identity
	session.SetPeerIdentity(peerRespPayload.Identity)

	h.logger.Info("unmask complete",
		"session", session.ID,
		"peer_display_name", peerRespPayload.Identity.GetDisplayName(),
	)

	return nil
}

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
	proto "github.com/mymonad/mymonad/pkg/protocol"
)

// ProtocolID is the libp2p protocol identifier for handshakes.
const ProtocolID = "/mymonad/handshake/1.0.0"

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
	// Stage 1: Send attestation request
	h.logger.Info("sending attestation request", "session", session.ID)

	// TODO: Implement full protocol stages in Tasks 12-15
	// For now, just a placeholder that will be expanded

	h.logger.Info("initiator protocol complete", "session", session.ID)
}

// runResponder runs the responder side of the protocol.
func (h *StreamHandler) runResponder(session *Session) {
	// Stage 1: Receive and respond to attestation
	h.logger.Info("waiting for attestation request", "session", session.ID)

	// TODO: Implement full protocol stages in Tasks 12-15

	h.logger.Info("responder protocol complete", "session", session.ID)
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

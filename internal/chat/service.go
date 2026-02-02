// Package chat provides encrypted chat functionality for the MyMonad protocol.
// This file implements the ChatService that manages multiple chat sessions.
package chat

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2pprotocol "github.com/libp2p/go-libp2p/core/protocol"
	"github.com/mymonad/mymonad/pkg/protocol"
)

// ChatProtocolID is the libp2p protocol identifier for chat streams.
const ChatProtocolID = "/mymonad/chat/1.0.0"

// Errors for service operations.
var (
	// ErrHandshakeSessionNotFound is returned when the handshake session does not exist.
	ErrHandshakeSessionNotFound = errors.New("chat: handshake session not found")

	// ErrSessionNotReady is returned when the session is not in a chat-ready state.
	ErrSessionNotReady = errors.New("chat: session not ready for chat")

	// ErrSessionFailed is returned when the session has failed.
	ErrSessionFailed = errors.New("chat: session has failed")

	// ErrStreamCreationFailed is returned when creating the chat stream fails.
	ErrStreamCreationFailed = errors.New("chat: stream creation failed")
)

// HandshakeSessionProvider defines the interface for accessing handshake session data.
// This abstraction allows for easier testing and decouples from the concrete handshake.Session type.
type HandshakeSessionProvider interface {
	// State returns the current handshake state.
	State() protocol.State

	// GetSharedSecret returns the shared secret derived during the handshake.
	GetSharedSecret() []byte

	// GetPeerID returns the peer's ID.
	GetPeerID() peer.ID
}

// HandshakeManagerProvider defines the interface for accessing the handshake manager.
// This abstraction allows for easier testing and decouples from the concrete handshake.Manager type.
type HandshakeManagerProvider interface {
	// GetSession returns a handshake session by its ID (hex-encoded).
	GetSession(id string) HandshakeSessionProvider
}

// StreamOpener defines the interface for opening new network streams.
// This abstraction allows for easier testing by mocking the host.
type StreamOpener interface {
	// NewStream opens a new stream to the given peer for the given protocols.
	NewStream(ctx context.Context, p peer.ID, pids ...libp2pprotocol.ID) (network.Stream, error)
}

// ChatService manages multiple chat sessions.
// It coordinates opening, closing, and accessing chat sessions.
type ChatService struct {
	mu           sync.RWMutex
	sessions     map[string]*ChatSession // Keyed by Session.ID hex
	host         StreamOpener
	handshakeMgr HandshakeManagerProvider
}

// NewChatService creates a new ChatService.
//
// Parameters:
//   - host: The libp2p host for opening streams
//   - handshakeMgr: The handshake manager for accessing session data
//
// Returns a new ChatService instance.
func NewChatService(host StreamOpener, handshakeMgr HandshakeManagerProvider) *ChatService {
	return &ChatService{
		sessions:     make(map[string]*ChatSession),
		host:         host,
		handshakeMgr: handshakeMgr,
	}
}

// OpenChat establishes a chat stream for an active handshake session.
// If a chat session already exists for the given session ID, it returns the existing session.
//
// Parameters:
//   - sessionID: The handshake session ID (raw bytes)
//
// Returns the ChatSession or an error if:
//   - The handshake session is not found
//   - The session is not in a chat-ready state (must be StateHumanChat or later)
//   - The session has failed
//   - Key derivation fails
//   - Stream creation fails
func (cs *ChatService) OpenChat(sessionID []byte) (*ChatSession, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	sidHex := hex.EncodeToString(sessionID)

	// Check for existing session
	if existing, ok := cs.sessions[sidHex]; ok {
		return existing, nil
	}

	// Get handshake session for shared secret and peer ID
	hsSession := cs.handshakeMgr.GetSession(sidHex)
	if hsSession == nil {
		return nil, ErrHandshakeSessionNotFound
	}

	// Verify session state
	state := hsSession.State()
	if err := validateStateForChat(state); err != nil {
		return nil, err
	}

	// Derive chat key using DeriveKey from crypto.go
	chatKey, err := DeriveKey(hsSession.GetSharedSecret(), sessionID)
	if err != nil {
		return nil, fmt.Errorf("derive chat key: %w", err)
	}

	// Open dedicated chat stream
	stream, err := cs.host.NewStream(
		context.Background(),
		hsSession.GetPeerID(),
		libp2pprotocol.ID(ChatProtocolID),
	)
	if err != nil {
		// Zero out the derived key before returning error
		zeroFill(chatKey)
		return nil, fmt.Errorf("%w: %v", ErrStreamCreationFailed, err)
	}

	// Create the session
	// Copy sessionID to avoid sharing the underlying array with the caller
	// This prevents zeroFill during Cleanup from affecting the caller's slice
	sessionIDCopy := make([]byte, len(sessionID))
	copy(sessionIDCopy, sessionID)

	session := &ChatSession{
		sessionID:    sessionIDCopy,
		peerID:       hsSession.GetPeerID(),
		chatKey:      chatKey,
		stream:       stream,
		streamRW:     stream, // network.Stream implements io.Reader and io.Writer
		messages:     make([]*StoredMessage, 0),
		pendingAcks:  make(map[string]*PendingMessage),
		isOpen:       true,
		lastActivity: time.Now(),
	}

	// Set up writeEnvelope to use the stream implementation
	session.writeEnvelope = session.writeEnvelopeImpl

	cs.sessions[sidHex] = session

	// Start read loop to handle incoming messages
	go session.readLoop()

	return session, nil
}

// GetSession returns a chat session by its ID.
// Returns nil if no session exists for the given ID.
//
// Parameters:
//   - sessionID: The session ID (raw bytes)
func (cs *ChatService) GetSession(sessionID []byte) *ChatSession {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	sidHex := hex.EncodeToString(sessionID)
	return cs.sessions[sidHex]
}

// CloseSession closes and removes a chat session.
// If no session exists for the given ID, this is a no-op.
//
// Parameters:
//   - sessionID: The session ID (raw bytes)
func (cs *ChatService) CloseSession(sessionID []byte) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	sidHex := hex.EncodeToString(sessionID)
	if session, ok := cs.sessions[sidHex]; ok {
		session.Cleanup()
		delete(cs.sessions, sidHex)
	}
}

// RegisterCleanup registers a callback to be called when the session is cleaned up.
// This is used to hook into the handshake session lifecycle.
// If no session exists for the given ID, this is a no-op.
//
// Parameters:
//   - sessionID: The session ID (raw bytes)
//   - callback: The function to call on cleanup
func (cs *ChatService) RegisterCleanup(sessionID []byte, callback func()) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	sidHex := hex.EncodeToString(sessionID)
	if session, ok := cs.sessions[sidHex]; ok {
		session.mu.Lock()
		session.onCleanup = callback
		session.mu.Unlock()
	}
}

// ListSessions returns all active chat sessions.
// Returns an empty slice if no sessions exist.
func (cs *ChatService) ListSessions() []*ChatSession {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	result := make([]*ChatSession, 0, len(cs.sessions))
	for _, session := range cs.sessions {
		result = append(result, session)
	}
	return result
}

// validateStateForChat checks if the handshake state allows chat.
// Chat is allowed in StateHumanChat, StateUnmask, and StateComplete.
func validateStateForChat(state protocol.State) error {
	switch state {
	case protocol.StateHumanChat, protocol.StateUnmask, protocol.StateComplete:
		return nil
	case protocol.StateFailed:
		return ErrSessionFailed
	default:
		return fmt.Errorf("%w: state=%s", ErrSessionNotReady, state)
	}
}

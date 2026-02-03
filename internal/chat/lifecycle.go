// Package chat provides encrypted chat functionality for the MyMonad protocol.
// This file implements lifecycle management for chat sessions, integrating with
// the handshake session state machine to automatically cleanup chat sessions
// when the handshake reaches a terminal state.
package chat

import (
	"encoding/hex"
	"log/slog"

	"github.com/mymonad/mymonad/pkg/protocol"
)

// HandshakeManagerWithStateChange extends HandshakeManagerProvider with state change callbacks.
// This interface allows the chat service to monitor handshake state transitions
// and cleanup chat sessions when the handshake reaches a terminal state.
type HandshakeManagerWithStateChange interface {
	HandshakeManagerProvider

	// OnStateChange registers a callback to be invoked when the handshake state changes.
	// The callback receives the new state after each transition.
	OnStateChange(sessionID []byte, callback func(protocol.State))
}

// monitorHandshakeState watches for terminal handshake states and cleans up the chat session.
// Terminal states are:
//   - StateComplete: The handshake succeeded and both parties unmasked.
//   - StateFailed: The handshake failed at some stage.
//
// Non-terminal states (like retries, renegotiation, StateUnmask) do NOT trigger cleanup.
// The chat survives during these transitions.
func (cs *ChatService) monitorHandshakeState(sessionID []byte) {
	sidHex := hex.EncodeToString(sessionID)

	// Check if handshake manager supports state change callbacks
	mgrWithStateChange, ok := cs.handshakeMgr.(HandshakeManagerWithStateChange)
	if !ok {
		slog.Warn("handshake manager does not support state change callbacks",
			"session_id", sidHex,
		)
		return
	}

	// Register callback for state changes
	mgrWithStateChange.OnStateChange(sessionID, func(newState protocol.State) {
		cs.handleStateChange(sidHex, newState)
	})
}

// handleStateChange processes a handshake state change and cleans up if terminal.
func (cs *ChatService) handleStateChange(sidHex string, newState protocol.State) {
	switch newState {
	case protocol.StateComplete:
		// Terminal success - cleanup chat
		slog.Info("handshake completed, closing chat",
			"session_id", sidHex,
			"state", newState,
		)
		cs.closeSession(sidHex)

	case protocol.StateFailed:
		// Terminal failure - cleanup chat
		slog.Info("handshake failed, closing chat",
			"session_id", sidHex,
			"state", newState,
		)
		cs.closeSession(sidHex)

	default:
		// Non-terminal states (retries, renegotiation): chat survives
		// No action needed - the chat session remains active
	}
}

// closeSession closes and removes a chat session by its hex-encoded session ID.
// If no session exists for the given ID, this is a no-op.
// This method is safe to call multiple times (idempotent).
func (cs *ChatService) closeSession(sidHex string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if session, ok := cs.sessions[sidHex]; ok {
		session.Cleanup()
		delete(cs.sessions, sidHex)
	}
}

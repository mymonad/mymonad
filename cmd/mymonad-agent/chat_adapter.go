package main

import (
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mymonad/mymonad/internal/chat"
	"github.com/mymonad/mymonad/internal/handshake"
	"github.com/mymonad/mymonad/pkg/protocol"
)

// handshakeSessionAdapter wraps a handshake.Session to implement chat.HandshakeSessionProvider.
type handshakeSessionAdapter struct {
	session *handshake.Session
}

// Ensure handshakeSessionAdapter implements chat.HandshakeSessionProvider
var _ chat.HandshakeSessionProvider = (*handshakeSessionAdapter)(nil)

// State returns the current handshake state.
func (a *handshakeSessionAdapter) State() protocol.State {
	return a.session.State()
}

// GetSharedSecret returns the shared secret derived during the handshake.
func (a *handshakeSessionAdapter) GetSharedSecret() []byte {
	return a.session.GetSharedSecret()
}

// GetPeerID returns the peer's ID.
func (a *handshakeSessionAdapter) GetPeerID() peer.ID {
	return a.session.GetPeerIDValue()
}

// handshakeManagerAdapter wraps a handshake.Manager to implement chat.HandshakeManagerProvider.
type handshakeManagerAdapter struct {
	manager *handshake.Manager
}

// Ensure handshakeManagerAdapter implements chat.HandshakeManagerProvider
var _ chat.HandshakeManagerProvider = (*handshakeManagerAdapter)(nil)

// GetSession returns a handshake session by its ID (hex-encoded).
// Returns nil if no session exists for the given ID.
func (a *handshakeManagerAdapter) GetSession(id string) chat.HandshakeSessionProvider {
	session := a.manager.GetSession(id)
	if session == nil {
		return nil
	}
	return &handshakeSessionAdapter{session: session}
}

// newHandshakeManagerAdapter creates a new adapter for the handshake manager.
func newHandshakeManagerAdapter(mgr *handshake.Manager) *handshakeManagerAdapter {
	return &handshakeManagerAdapter{manager: mgr}
}

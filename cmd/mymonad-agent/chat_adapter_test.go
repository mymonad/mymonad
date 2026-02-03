package main

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mymonad/mymonad/internal/chat"
	"github.com/mymonad/mymonad/internal/handshake"
	"github.com/mymonad/mymonad/pkg/protocol"
)

// ============================================================================
// handshakeSessionAdapter tests
// ============================================================================

func TestHandshakeSessionAdapter_State(t *testing.T) {
	peerID := peer.ID("test-peer")
	session := handshake.NewSession(peerID, protocol.RoleInitiator, 0.85)

	adapter := &handshakeSessionAdapter{session: session}

	// Initial state should be Idle
	state := adapter.State()
	if state != protocol.StateIdle {
		t.Errorf("State() = %s, want %s", state, protocol.StateIdle)
	}

	// Transition the session and verify adapter reflects change
	session.Handshake.Transition(protocol.EventInitiate)
	state = adapter.State()
	if state != protocol.StateAttestation {
		t.Errorf("State() after transition = %s, want %s", state, protocol.StateAttestation)
	}
}

func TestHandshakeSessionAdapter_GetSharedSecret(t *testing.T) {
	peerID := peer.ID("test-peer")
	session := handshake.NewSession(peerID, protocol.RoleInitiator, 0.85)

	adapter := &handshakeSessionAdapter{session: session}

	// Initially no shared secret
	secret := adapter.GetSharedSecret()
	if secret != nil {
		t.Error("GetSharedSecret() should return nil when no secret is set")
	}

	// Set a shared secret
	testSecret := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	session.SetSharedSecret(testSecret)

	// Verify adapter returns the secret
	secret = adapter.GetSharedSecret()
	if secret == nil {
		t.Fatal("GetSharedSecret() should return the secret after it's set")
	}
	if len(secret) != len(testSecret) {
		t.Errorf("GetSharedSecret() length = %d, want %d", len(secret), len(testSecret))
	}
	for i := range testSecret {
		if secret[i] != testSecret[i] {
			t.Errorf("GetSharedSecret()[%d] = %02x, want %02x", i, secret[i], testSecret[i])
		}
	}
}

func TestHandshakeSessionAdapter_GetSharedSecret_ReturnsCopy(t *testing.T) {
	peerID := peer.ID("test-peer")
	session := handshake.NewSession(peerID, protocol.RoleInitiator, 0.85)

	adapter := &handshakeSessionAdapter{session: session}

	testSecret := []byte{0x01, 0x02, 0x03, 0x04}
	session.SetSharedSecret(testSecret)

	// Get the secret and modify it
	secret := adapter.GetSharedSecret()
	secret[0] = 0xFF

	// Original should be unchanged
	original := adapter.GetSharedSecret()
	if original[0] != 0x01 {
		t.Error("GetSharedSecret() should return a copy, not the original")
	}
}

func TestHandshakeSessionAdapter_GetPeerID(t *testing.T) {
	expectedPeerID := peer.ID("test-peer-123")
	session := handshake.NewSession(expectedPeerID, protocol.RoleInitiator, 0.85)

	adapter := &handshakeSessionAdapter{session: session}

	peerID := adapter.GetPeerID()
	if peerID != expectedPeerID {
		t.Errorf("GetPeerID() = %s, want %s", peerID, expectedPeerID)
	}
}

func TestHandshakeSessionAdapter_ImplementsInterface(t *testing.T) {
	// Compile-time interface check
	var _ chat.HandshakeSessionProvider = (*handshakeSessionAdapter)(nil)
}

// ============================================================================
// handshakeManagerAdapter tests
// ============================================================================

func TestHandshakeManagerAdapter_GetSession_NotFound(t *testing.T) {
	// Create a minimal host mock - we just need a manager
	// The manager needs a host, so we'll create a real daemon to get one
	tmpDir := t.TempDir()

	cfg := DaemonConfig{
		SocketPath:          tmpDir + "/agent.sock",
		IdentityPath:        tmpDir + "/identity.key",
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        tmpDir + "/ingest.sock",
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	defer d.Close()

	adapter := newHandshakeManagerAdapter(d.handshakeManager)

	// Try to get a non-existent session
	session := adapter.GetSession("nonexistent-session-id")
	if session != nil {
		t.Error("GetSession() should return nil for non-existent session")
	}
}

func TestHandshakeManagerAdapter_GetSession_Found(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := DaemonConfig{
		SocketPath:          tmpDir + "/agent.sock",
		IdentityPath:        tmpDir + "/identity.key",
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        tmpDir + "/ingest.sock",
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	defer d.Close()

	adapter := newHandshakeManagerAdapter(d.handshakeManager)

	// Create a session directly in the manager
	peerID := peer.ID("test-peer")
	session := d.handshakeManager.CreateSession(peerID, protocol.RoleInitiator)

	// Get the session via adapter
	retrieved := adapter.GetSession(session.ID)
	if retrieved == nil {
		t.Fatal("GetSession() should return the session")
	}

	// Verify the adapter wraps the session correctly
	if retrieved.GetPeerID() != peerID {
		t.Errorf("GetPeerID() = %s, want %s", retrieved.GetPeerID(), peerID)
	}
}

func TestHandshakeManagerAdapter_GetSession_ReturnsAdapter(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := DaemonConfig{
		SocketPath:          tmpDir + "/agent.sock",
		IdentityPath:        tmpDir + "/identity.key",
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        tmpDir + "/ingest.sock",
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	defer d.Close()

	adapter := newHandshakeManagerAdapter(d.handshakeManager)

	// Create a session
	peerID := peer.ID("test-peer")
	session := d.handshakeManager.CreateSession(peerID, protocol.RoleInitiator)

	// Set a shared secret on the underlying session
	testSecret := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	session.SetSharedSecret(testSecret)

	// Get via adapter and verify shared secret is accessible
	retrieved := adapter.GetSession(session.ID)
	if retrieved == nil {
		t.Fatal("GetSession() should return the session")
	}

	secret := retrieved.GetSharedSecret()
	if len(secret) != len(testSecret) {
		t.Errorf("GetSharedSecret() length = %d, want %d", len(secret), len(testSecret))
	}
}

func TestHandshakeManagerAdapter_ImplementsInterface(t *testing.T) {
	// Compile-time interface check
	var _ chat.HandshakeManagerProvider = (*handshakeManagerAdapter)(nil)
}

// ============================================================================
// Session cleanup tests (SharedSecret zeroed)
// ============================================================================

func TestSession_SharedSecret_ZeroedOnCleanup(t *testing.T) {
	peerID := peer.ID("test-peer")
	session := handshake.NewSession(peerID, protocol.RoleInitiator, 0.85)

	// Set a shared secret
	testSecret := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	session.SetSharedSecret(testSecret)

	// Verify it's set
	if session.GetSharedSecret() == nil {
		t.Fatal("SharedSecret should be set before cleanup")
	}

	// Cleanup
	session.Cleanup()

	// Give a moment for cleanup to complete
	time.Sleep(10 * time.Millisecond)

	// Verify it's nil after cleanup
	if session.GetSharedSecret() != nil {
		t.Error("SharedSecret should be nil after cleanup")
	}
}

package handshake

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mymonad/mymonad/pkg/protocol"
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

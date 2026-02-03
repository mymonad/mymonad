// Package chat provides encrypted chat functionality for the MyMonad protocol.
// This file contains tests for the lifecycle management functionality.
package chat

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2pprotocol "github.com/libp2p/go-libp2p/core/protocol"
	"github.com/mymonad/mymonad/pkg/protocol"
)

// ============================================================================
// Extended mock for state change callbacks
// ============================================================================

// blockingMockStream is a mock stream that blocks on Read until closed.
// This is used to prevent the read loop from immediately closing the session.
type blockingMockStream struct {
	*mockStream
	closeCh chan struct{}
}

func newBlockingMockStream() *blockingMockStream {
	return &blockingMockStream{
		mockStream: newMockStream(),
		closeCh:    make(chan struct{}),
	}
}

func (b *blockingMockStream) Read(p []byte) (n int, err error) {
	// Block until closed
	<-b.closeCh
	return 0, io.EOF
}

func (b *blockingMockStream) Close() error {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		close(b.closeCh)
	}
	b.mu.Unlock()
	return nil
}

// blockingMockHost creates blocking streams that don't immediately EOF.
type blockingMockHost struct {
	*mockHost
	blockingStream *blockingMockStream
}

func newBlockingMockHost() *blockingMockHost {
	return &blockingMockHost{
		mockHost: newMockHost(),
	}
}

func (h *blockingMockHost) NewStream(ctx context.Context, p peer.ID, pids ...libp2pprotocol.ID) (network.Stream, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.shouldFail {
		if h.failError != nil {
			return nil, h.failError
		}
		return nil, errors.New("mock: stream creation failed")
	}

	stream := newBlockingMockStream()
	h.blockingStream = stream
	h.streams[p] = stream.mockStream
	h.createdStream = stream.mockStream
	return stream, nil
}

// stateChangeCallback represents a registered state change callback.
type stateChangeCallback struct {
	sessionID []byte
	callback  func(protocol.State)
}

// mockHandshakeManagerWithStateChange extends mockHandshakeManager with OnStateChange support.
type mockHandshakeManagerWithStateChange struct {
	mu        sync.RWMutex
	sessions  map[string]*mockHandshakeSession
	callbacks map[string][]func(protocol.State) // Keyed by session ID hex
}

func newMockHandshakeManagerWithStateChange() *mockHandshakeManagerWithStateChange {
	return &mockHandshakeManagerWithStateChange{
		sessions:  make(map[string]*mockHandshakeSession),
		callbacks: make(map[string][]func(protocol.State)),
	}
}

func (m *mockHandshakeManagerWithStateChange) GetSession(id string) HandshakeSessionProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if s, ok := m.sessions[id]; ok {
		return s
	}
	return nil
}

func (m *mockHandshakeManagerWithStateChange) OnStateChange(sessionID []byte, callback func(protocol.State)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sidHex := hex.EncodeToString(sessionID)
	m.callbacks[sidHex] = append(m.callbacks[sidHex], callback)
}

func (m *mockHandshakeManagerWithStateChange) addSession(id string, session *mockHandshakeSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[id] = session
}

// simulateStateChange triggers all registered callbacks for a session.
func (m *mockHandshakeManagerWithStateChange) simulateStateChange(sessionID []byte, newState protocol.State) {
	m.mu.RLock()
	sidHex := hex.EncodeToString(sessionID)
	callbacks := m.callbacks[sidHex]
	m.mu.RUnlock()

	for _, cb := range callbacks {
		cb(newState)
	}
}

// ============================================================================
// monitorHandshakeState tests
// ============================================================================

func TestMonitorHandshakeState_RegistersCallbackWithManager(t *testing.T) {
	mgr := newMockHandshakeManagerWithStateChange()
	host := newMockHost()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	// Set up handshake session
	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	// Open chat session first
	_, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("failed to open chat: %v", err)
	}

	// Monitor handshake state
	svc.monitorHandshakeState(sessionID)

	// Verify callback was registered
	mgr.mu.RLock()
	callbacks := mgr.callbacks[sidHex]
	mgr.mu.RUnlock()

	if len(callbacks) == 0 {
		t.Error("expected callback to be registered with handshake manager")
	}
}

func TestMonitorHandshakeState_StateComplete_ClosesSession(t *testing.T) {
	mgr := newMockHandshakeManagerWithStateChange()
	host := newMockHost()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	// Set up handshake session
	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	// Open chat session first
	_, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("failed to open chat: %v", err)
	}

	// Verify session exists
	if svc.GetSession(sessionID) == nil {
		t.Fatal("session should exist before state change")
	}

	// Monitor handshake state
	svc.monitorHandshakeState(sessionID)

	// Simulate terminal state (Complete = success)
	mgr.simulateStateChange(sessionID, protocol.StateComplete)

	// Give goroutine time to process
	time.Sleep(10 * time.Millisecond)

	// Verify session was closed
	if svc.GetSession(sessionID) != nil {
		t.Error("session should be removed after StateComplete")
	}
}

func TestMonitorHandshakeState_StateFailed_ClosesSession(t *testing.T) {
	mgr := newMockHandshakeManagerWithStateChange()
	host := newMockHost()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	// Set up handshake session
	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	// Open chat session
	_, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("failed to open chat: %v", err)
	}

	// Monitor handshake state
	svc.monitorHandshakeState(sessionID)

	// Simulate terminal state (Failed)
	mgr.simulateStateChange(sessionID, protocol.StateFailed)

	// Give goroutine time to process
	time.Sleep(10 * time.Millisecond)

	// Verify session was closed
	if svc.GetSession(sessionID) != nil {
		t.Error("session should be removed after StateFailed")
	}
}

func TestMonitorHandshakeState_NonTerminalState_SessionSurvives(t *testing.T) {
	mgr := newMockHandshakeManagerWithStateChange()
	// Use blocking host so stream doesn't immediately EOF
	host := newBlockingMockHost()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	// Set up handshake session
	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	// Open chat session
	session, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("failed to open chat: %v", err)
	}

	// Monitor handshake state
	svc.monitorHandshakeState(sessionID)

	// Test various non-terminal states
	nonTerminalStates := []protocol.State{
		protocol.StateUnmask, // Still in progress
	}

	for _, state := range nonTerminalStates {
		mgr.simulateStateChange(sessionID, state)
		time.Sleep(10 * time.Millisecond)

		// Verify session still exists
		if svc.GetSession(sessionID) == nil {
			t.Errorf("session should survive non-terminal state %s", state)
		}

		// Verify session is still open
		session.mu.RLock()
		isOpen := session.isOpen
		session.mu.RUnlock()
		if !isOpen {
			t.Errorf("session should still be open after non-terminal state %s", state)
		}
	}

	// Cleanup: close the blocking stream to let the read loop exit
	if host.blockingStream != nil {
		host.blockingStream.Close()
	}
}

// ============================================================================
// closeSession tests (internal method via sidHex)
// ============================================================================

func TestCloseSessionByHex_RemovesFromMap(t *testing.T) {
	mgr := newMockHandshakeManagerWithStateChange()
	host := newMockHost()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	// Set up handshake session
	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	// Open chat session
	_, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("failed to open chat: %v", err)
	}

	// Verify session exists
	svc.mu.RLock()
	_, exists := svc.sessions[sidHex]
	svc.mu.RUnlock()
	if !exists {
		t.Fatal("session should exist before close")
	}

	// Close session by hex ID
	svc.closeSession(sidHex)

	// Verify session is removed
	svc.mu.RLock()
	_, exists = svc.sessions[sidHex]
	svc.mu.RUnlock()
	if exists {
		t.Error("session should be removed after closeSession")
	}
}

func TestCloseSessionByHex_CallsCleanup(t *testing.T) {
	mgr := newMockHandshakeManagerWithStateChange()
	host := newMockHost()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	// Set up handshake session
	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	// Open chat session
	session, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("failed to open chat: %v", err)
	}

	// Close session by hex ID
	svc.closeSession(sidHex)

	// Verify session was cleaned up
	session.mu.RLock()
	isOpen := session.isOpen
	session.mu.RUnlock()

	if isOpen {
		t.Error("session should be closed after closeSession")
	}
}

func TestCloseSessionByHex_NonExistent_NoOp(t *testing.T) {
	mgr := newMockHandshakeManagerWithStateChange()
	host := newMockHost()
	svc := NewChatService(host, mgr)

	// Should not panic
	svc.closeSession("nonexistent-session-id")
}

func TestCloseSessionByHex_Idempotent(t *testing.T) {
	mgr := newMockHandshakeManagerWithStateChange()
	host := newMockHost()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	// Set up handshake session
	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	// Open chat session
	_, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("failed to open chat: %v", err)
	}

	// Close multiple times - should not panic
	svc.closeSession(sidHex)
	svc.closeSession(sidHex)
	svc.closeSession(sidHex)

	// Verify session is removed
	if svc.GetSession(sessionID) != nil {
		t.Error("session should be removed")
	}
}

// ============================================================================
// Terminal state cleanup integration tests
// ============================================================================

func TestTerminalState_Complete_FullCleanup(t *testing.T) {
	mgr := newMockHandshakeManagerWithStateChange()
	host := newMockHost()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	// Set up handshake session
	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	// Open chat and monitor
	session, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("failed to open chat: %v", err)
	}

	// Track cleanup callback
	cleanupCalled := false
	svc.RegisterCleanup(sessionID, func() {
		cleanupCalled = true
	})

	svc.monitorHandshakeState(sessionID)

	// Simulate terminal success state
	mgr.simulateStateChange(sessionID, protocol.StateComplete)
	time.Sleep(10 * time.Millisecond)

	// Verify full cleanup
	session.mu.RLock()
	isOpen := session.isOpen
	session.mu.RUnlock()

	if isOpen {
		t.Error("session should be cleaned up")
	}
	if !cleanupCalled {
		t.Error("cleanup callback should have been called")
	}
	if svc.GetSession(sessionID) != nil {
		t.Error("session should be removed from service")
	}
}

func TestTerminalState_Failed_FullCleanup(t *testing.T) {
	mgr := newMockHandshakeManagerWithStateChange()
	host := newMockHost()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	// Set up handshake session
	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	// Open chat and monitor
	session, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("failed to open chat: %v", err)
	}

	// Track cleanup callback
	cleanupCalled := false
	svc.RegisterCleanup(sessionID, func() {
		cleanupCalled = true
	})

	svc.monitorHandshakeState(sessionID)

	// Simulate terminal failure state
	mgr.simulateStateChange(sessionID, protocol.StateFailed)
	time.Sleep(10 * time.Millisecond)

	// Verify full cleanup
	session.mu.RLock()
	isOpen := session.isOpen
	session.mu.RUnlock()

	if isOpen {
		t.Error("session should be cleaned up")
	}
	if !cleanupCalled {
		t.Error("cleanup callback should have been called")
	}
	if svc.GetSession(sessionID) != nil {
		t.Error("session should be removed from service")
	}
}

// ============================================================================
// Concurrent access tests
// ============================================================================

func TestMonitorHandshakeState_ConcurrentStateChanges(t *testing.T) {
	mgr := newMockHandshakeManagerWithStateChange()
	host := newMockHost()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	// Set up handshake session
	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	// Open chat and monitor
	_, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("failed to open chat: %v", err)
	}
	svc.monitorHandshakeState(sessionID)

	// Simulate multiple concurrent state changes
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Mix of terminal and non-terminal states
			mgr.simulateStateChange(sessionID, protocol.StateUnmask)
			mgr.simulateStateChange(sessionID, protocol.StateComplete)
		}()
	}
	wg.Wait()

	// Give time for callbacks to process
	time.Sleep(50 * time.Millisecond)

	// Session should be closed due to at least one terminal state
	if svc.GetSession(sessionID) != nil {
		t.Error("session should be removed after terminal state")
	}
}

func TestCloseSession_ConcurrentCalls(t *testing.T) {
	mgr := newMockHandshakeManagerWithStateChange()
	host := newMockHost()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	// Set up handshake session
	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	// Open chat session
	_, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("failed to open chat: %v", err)
	}

	// Close concurrently
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			svc.closeSession(sidHex)
		}()
	}
	wg.Wait()

	// Verify session is removed
	if svc.GetSession(sessionID) != nil {
		t.Error("session should be removed")
	}
}

// ============================================================================
// Interface extension tests
// ============================================================================

func TestHandshakeManagerWithStateChange_ImplementsProvider(t *testing.T) {
	mgr := newMockHandshakeManagerWithStateChange()

	// Verify it satisfies HandshakeManagerProvider
	var _ HandshakeManagerProvider = mgr

	// Verify it satisfies HandshakeManagerWithStateChange
	var _ HandshakeManagerWithStateChange = mgr
}

// ============================================================================
// Edge cases
// ============================================================================

func TestMonitorHandshakeState_SessionNotFound_NoOp(t *testing.T) {
	mgr := newMockHandshakeManagerWithStateChange()
	host := newMockHost()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()

	// Should not panic when session doesn't exist
	svc.monitorHandshakeState(sessionID)

	// State changes should not cause panic
	mgr.simulateStateChange(sessionID, protocol.StateComplete)
}

func TestMonitorHandshakeState_MultipleCallsForSameSession(t *testing.T) {
	mgr := newMockHandshakeManagerWithStateChange()
	host := newMockHost()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	// Set up handshake session
	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	// Open chat session
	_, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("failed to open chat: %v", err)
	}

	// Call monitor multiple times - should not panic
	svc.monitorHandshakeState(sessionID)
	svc.monitorHandshakeState(sessionID)
	svc.monitorHandshakeState(sessionID)

	// Trigger state change - all callbacks will fire but session close should be idempotent
	mgr.simulateStateChange(sessionID, protocol.StateComplete)
	time.Sleep(10 * time.Millisecond)

	// Verify session is removed
	if svc.GetSession(sessionID) != nil {
		t.Error("session should be removed")
	}
}

// ============================================================================
// OpenChat integration with lifecycle monitoring
// ============================================================================

func TestOpenChatWithMonitoring_IntegrationFlow(t *testing.T) {
	mgr := newMockHandshakeManagerWithStateChange()
	host := newMockHost()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)
	peerID := peer.ID("test-peer-integration")

	// Set up handshake session
	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       peerID,
	})

	// Simulate the full flow: open chat, register cleanup, monitor state
	session, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("failed to open chat: %v", err)
	}

	cleanupCalled := make(chan bool, 1)
	svc.RegisterCleanup(sessionID, func() {
		cleanupCalled <- true
	})

	svc.monitorHandshakeState(sessionID)

	// Verify session is active
	if !session.isOpen {
		t.Error("session should be open initially")
	}

	// Simulate handshake completion
	mgr.simulateStateChange(sessionID, protocol.StateComplete)

	// Wait for cleanup with timeout
	select {
	case <-cleanupCalled:
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Error("cleanup callback should have been called")
	}

	// Verify cleanup
	if svc.GetSession(sessionID) != nil {
		t.Error("session should be removed after handshake completion")
	}
}

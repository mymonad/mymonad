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
// Mock implementations for testing
// ============================================================================

// mockHandshakeSession implements HandshakeSessionProvider for testing.
type mockHandshakeSession struct {
	state        protocol.State
	sharedSecret []byte
	peerID       peer.ID
}

func (m *mockHandshakeSession) State() protocol.State {
	return m.state
}

func (m *mockHandshakeSession) GetSharedSecret() []byte {
	return m.sharedSecret
}

func (m *mockHandshakeSession) GetPeerID() peer.ID {
	return m.peerID
}

// mockHandshakeManager implements HandshakeManagerProvider for testing.
type mockHandshakeManager struct {
	mu       sync.RWMutex
	sessions map[string]*mockHandshakeSession
}

func newMockHandshakeManager() *mockHandshakeManager {
	return &mockHandshakeManager{
		sessions: make(map[string]*mockHandshakeSession),
	}
}

func (m *mockHandshakeManager) GetSession(id string) HandshakeSessionProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if s, ok := m.sessions[id]; ok {
		return s
	}
	return nil
}

func (m *mockHandshakeManager) addSession(id string, session *mockHandshakeSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[id] = session
}

// mockStream implements network.Stream for testing.
type mockStream struct {
	mu       sync.Mutex
	closed   bool
	protocol libp2pprotocol.ID
	conn     network.Conn
	readBuf  []byte
	readPos  int
	written  []byte
}

func newMockStream() *mockStream {
	return &mockStream{
		protocol: "/mymonad/chat/1.0.0",
	}
}

func (m *mockStream) Read(p []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, io.EOF
	}
	if m.readPos >= len(m.readBuf) {
		return 0, io.EOF
	}
	n = copy(p, m.readBuf[m.readPos:])
	m.readPos += n
	return n, nil
}

func (m *mockStream) Write(p []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, errors.New("stream closed")
	}
	m.written = append(m.written, p...)
	return len(p), nil
}

func (m *mockStream) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockStream) CloseRead() error {
	return nil
}

func (m *mockStream) CloseWrite() error {
	return nil
}

func (m *mockStream) Reset() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockStream) ResetWithError(_ network.StreamErrorCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockStream) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockStream) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockStream) SetWriteDeadline(t time.Time) error {
	return nil
}

func (m *mockStream) Protocol() libp2pprotocol.ID {
	return m.protocol
}

func (m *mockStream) SetProtocol(id libp2pprotocol.ID) error {
	m.protocol = id
	return nil
}

func (m *mockStream) Stat() network.Stats {
	return network.Stats{}
}

func (m *mockStream) Conn() network.Conn {
	return m.conn
}

func (m *mockStream) ID() string {
	return "mock-stream-id"
}

func (m *mockStream) Scope() network.StreamScope {
	return nil
}

func (m *mockStream) IsClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// mockHost implements StreamOpener for testing.
type mockHost struct {
	mu            sync.Mutex
	streams       map[peer.ID]*mockStream
	shouldFail    bool
	failError     error
	createdStream *mockStream
}

func newMockHost() *mockHost {
	return &mockHost{
		streams: make(map[peer.ID]*mockStream),
	}
}

func (m *mockHost) NewStream(ctx context.Context, p peer.ID, pids ...libp2pprotocol.ID) (network.Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldFail {
		if m.failError != nil {
			return nil, m.failError
		}
		return nil, errors.New("mock: stream creation failed")
	}

	stream := newMockStream()
	m.streams[p] = stream
	m.createdStream = stream
	return stream, nil
}

func (m *mockHost) setFailure(fail bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFail = fail
	m.failError = err
}

func (m *mockHost) getCreatedStream() *mockStream {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.createdStream
}

// ============================================================================
// Test helpers
// ============================================================================

func createTestSessionID() []byte {
	return []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
}

func createTestSharedSecret() []byte {
	return []byte{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
	}
}

func createTestPeerID() peer.ID {
	return peer.ID("test-peer-12345")
}

// ============================================================================
// NewChatService tests
// ============================================================================

func TestNewChatService_CreatesEmptySessionsMap(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()

	svc := NewChatService(host, mgr)

	if svc == nil {
		t.Fatal("NewChatService returned nil")
	}
	if svc.sessions == nil {
		t.Error("sessions map should be initialized")
	}
	if len(svc.sessions) != 0 {
		t.Errorf("sessions map should be empty, got %d entries", len(svc.sessions))
	}
}

func TestNewChatService_StoresHostReference(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()

	svc := NewChatService(host, mgr)

	if svc.host != host {
		t.Error("host reference not stored correctly")
	}
}

func TestNewChatService_StoresManagerReference(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()

	svc := NewChatService(host, mgr)

	if svc.handshakeMgr != mgr {
		t.Error("handshake manager reference not stored correctly")
	}
}

// ============================================================================
// OpenChat tests - session not found
// ============================================================================

func TestOpenChat_SessionNotFound_ReturnsError(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()

	_, err := svc.OpenChat(sessionID)

	if err == nil {
		t.Fatal("expected error for missing session")
	}
	if !errors.Is(err, ErrHandshakeSessionNotFound) {
		t.Errorf("expected ErrHandshakeSessionNotFound, got: %v", err)
	}
}

// ============================================================================
// OpenChat tests - state validation
// ============================================================================

func TestOpenChat_StateIdle_ReturnsError(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateIdle,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	_, err := svc.OpenChat(sessionID)

	if err == nil {
		t.Fatal("expected error for Idle state")
	}
	if !errors.Is(err, ErrSessionNotReady) {
		t.Errorf("expected ErrSessionNotReady, got: %v", err)
	}
}

func TestOpenChat_StateAttestation_ReturnsError(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateAttestation,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	_, err := svc.OpenChat(sessionID)

	if err == nil {
		t.Fatal("expected error for Attestation state")
	}
	if !errors.Is(err, ErrSessionNotReady) {
		t.Errorf("expected ErrSessionNotReady, got: %v", err)
	}
}

func TestOpenChat_StateVectorMatch_ReturnsError(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateVectorMatch,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	_, err := svc.OpenChat(sessionID)

	if err == nil {
		t.Fatal("expected error for VectorMatch state")
	}
	if !errors.Is(err, ErrSessionNotReady) {
		t.Errorf("expected ErrSessionNotReady, got: %v", err)
	}
}

func TestOpenChat_StateDealBreakers_ReturnsError(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateDealBreakers,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	_, err := svc.OpenChat(sessionID)

	if err == nil {
		t.Fatal("expected error for DealBreakers state")
	}
	if !errors.Is(err, ErrSessionNotReady) {
		t.Errorf("expected ErrSessionNotReady, got: %v", err)
	}
}

func TestOpenChat_StateHumanChat_Success(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	session, err := svc.OpenChat(sessionID)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session == nil {
		t.Fatal("expected session to be returned")
	}
	if !session.isOpen {
		t.Error("session should be open")
	}
}

func TestOpenChat_StateUnmask_Success(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateUnmask,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	session, err := svc.OpenChat(sessionID)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session == nil {
		t.Fatal("expected session to be returned")
	}
}

func TestOpenChat_StateComplete_Success(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateComplete,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	session, err := svc.OpenChat(sessionID)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session == nil {
		t.Fatal("expected session to be returned")
	}
}

func TestOpenChat_StateFailed_ReturnsError(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateFailed,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	_, err := svc.OpenChat(sessionID)

	if err == nil {
		t.Fatal("expected error for Failed state")
	}
	if !errors.Is(err, ErrSessionFailed) {
		t.Errorf("expected ErrSessionFailed, got: %v", err)
	}
}

// ============================================================================
// OpenChat tests - duplicate session handling
// ============================================================================

func TestOpenChat_DuplicateSession_ReturnsExisting(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	// First open
	session1, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("first open failed: %v", err)
	}

	// Second open should return same session
	session2, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("second open failed: %v", err)
	}

	if session1 != session2 {
		t.Error("expected same session instance on duplicate open")
	}
}

func TestOpenChat_DuplicateSession_DoesNotCreateNewStream(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	// First open creates a stream
	_, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("first open failed: %v", err)
	}
	firstStream := host.getCreatedStream()

	// Second open should NOT create a new stream
	host.setFailure(true, errors.New("should not be called"))
	_, err = svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("second open failed: %v", err)
	}

	// Verify no new stream was created
	if host.getCreatedStream() != firstStream {
		t.Error("should not have created a new stream for duplicate session")
	}
}

// ============================================================================
// OpenChat tests - key derivation
// ============================================================================

func TestOpenChat_DerivesCorrectKey(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)
	sharedSecret := createTestSharedSecret()

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: sharedSecret,
		peerID:       createTestPeerID(),
	})

	session, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the key was derived correctly
	expectedKey, err := DeriveKey(sharedSecret, sessionID)
	if err != nil {
		t.Fatalf("failed to derive expected key: %v", err)
	}

	session.mu.RLock()
	defer session.mu.RUnlock()

	if len(session.chatKey) != ChatKeyLength {
		t.Errorf("chat key length: expected %d, got %d", ChatKeyLength, len(session.chatKey))
	}

	for i := range expectedKey {
		if session.chatKey[i] != expectedKey[i] {
			t.Errorf("chat key mismatch at byte %d: expected %02x, got %02x",
				i, expectedKey[i], session.chatKey[i])
		}
	}
}

func TestOpenChat_InvalidSharedSecret_ReturnsError(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: nil, // Invalid: nil shared secret
		peerID:       createTestPeerID(),
	})

	_, err := svc.OpenChat(sessionID)

	if err == nil {
		t.Fatal("expected error for nil shared secret")
	}
}

func TestOpenChat_EmptySharedSecret_ReturnsError(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: []byte{}, // Invalid: empty shared secret
		peerID:       createTestPeerID(),
	})

	_, err := svc.OpenChat(sessionID)

	if err == nil {
		t.Fatal("expected error for empty shared secret")
	}
}

// ============================================================================
// OpenChat tests - stream creation
// ============================================================================

func TestOpenChat_StreamCreationFails_ReturnsError(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	host.setFailure(true, errors.New("peer unreachable"))

	_, err := svc.OpenChat(sessionID)

	if err == nil {
		t.Fatal("expected error when stream creation fails")
	}
	if !errors.Is(err, ErrStreamCreationFailed) {
		t.Errorf("expected ErrStreamCreationFailed, got: %v", err)
	}
}

func TestOpenChat_SetsCorrectPeerID(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)
	expectedPeerID := createTestPeerID()

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       expectedPeerID,
	})

	session, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	session.mu.RLock()
	defer session.mu.RUnlock()

	if session.peerID != expectedPeerID {
		t.Errorf("peer ID mismatch: expected %s, got %s", expectedPeerID, session.peerID)
	}
}

// ============================================================================
// OpenChat tests - session initialization
// ============================================================================

func TestOpenChat_InitializesSessionCorrectly(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	before := time.Now()
	session, err := svc.OpenChat(sessionID)
	after := time.Now()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	session.mu.RLock()
	defer session.mu.RUnlock()

	// Verify sessionID
	if len(session.sessionID) != len(sessionID) {
		t.Errorf("session ID length mismatch")
	}

	// Verify messages buffer is initialized
	if session.messages == nil {
		t.Error("messages should be initialized")
	}

	// Verify pendingAcks map is initialized
	if session.pendingAcks == nil {
		t.Error("pendingAcks should be initialized")
	}

	// Verify isOpen flag
	if !session.isOpen {
		t.Error("session should be open")
	}

	// Verify lastActivity is set
	if session.lastActivity.Before(before) || session.lastActivity.After(after) {
		t.Error("lastActivity should be set to current time")
	}

	// Verify stream is set
	if session.stream == nil {
		t.Error("stream should be set")
	}
}

func TestOpenChat_StoresSessionInMap(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	session, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify session is stored in the service's map
	svc.mu.RLock()
	stored, ok := svc.sessions[sidHex]
	svc.mu.RUnlock()

	if !ok {
		t.Error("session should be stored in service map")
	}
	if stored != session {
		t.Error("stored session should match returned session")
	}
}

// ============================================================================
// GetSession tests
// ============================================================================

func TestGetSession_Existing_ReturnsSession(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	created, _ := svc.OpenChat(sessionID)

	retrieved := svc.GetSession(sessionID)

	if retrieved != created {
		t.Error("GetSession should return the same session instance")
	}
}

func TestGetSession_NotExisting_ReturnsNil(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()

	retrieved := svc.GetSession(sessionID)

	if retrieved != nil {
		t.Error("GetSession should return nil for non-existent session")
	}
}

// ============================================================================
// CloseSession tests
// ============================================================================

func TestCloseSession_ExistingSession_RemovesFromMap(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	_, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	svc.CloseSession(sessionID)

	// Verify session is removed
	svc.mu.RLock()
	_, ok := svc.sessions[sidHex]
	svc.mu.RUnlock()

	if ok {
		t.Error("session should be removed from map after close")
	}
}

func TestCloseSession_ExistingSession_CallsCleanup(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	session, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	svc.CloseSession(sessionID)

	// Verify session is closed
	session.mu.RLock()
	isOpen := session.isOpen
	session.mu.RUnlock()

	if isOpen {
		t.Error("session should be closed after CloseSession")
	}
}

func TestCloseSession_NonExistingSession_DoesNotPanic(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()

	// Should not panic
	svc.CloseSession(sessionID)
}

// ============================================================================
// RegisterCleanup tests
// ============================================================================

func TestRegisterCleanup_SetsCallback(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	session, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	called := false
	svc.RegisterCleanup(sessionID, func() {
		called = true
	})

	// Trigger cleanup
	session.Cleanup()

	if !called {
		t.Error("cleanup callback should have been called")
	}
}

func TestRegisterCleanup_NonExistingSession_DoesNotPanic(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()

	// Should not panic
	svc.RegisterCleanup(sessionID, func() {})
}

// ============================================================================
// Concurrent access tests
// ============================================================================

func TestOpenChat_ConcurrentAccess_ThreadSafe(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	var wg sync.WaitGroup
	sessions := make([]*ChatSession, 10)
	errs := make([]error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			s, err := svc.OpenChat(sessionID)
			sessions[idx] = s
			errs[idx] = err
		}(i)
	}

	wg.Wait()

	// All should succeed or return the same session
	var firstSession *ChatSession
	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d failed: %v", i, err)
			continue
		}
		if firstSession == nil {
			firstSession = sessions[i]
		} else if sessions[i] != firstSession {
			t.Error("all goroutines should get the same session instance")
		}
	}
}

func TestService_ConcurrentOpenAndClose_ThreadSafe(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessionID := createTestSessionID()
	sidHex := hex.EncodeToString(sessionID)

	mgr.addSession(sidHex, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       createTestPeerID(),
	})

	var wg sync.WaitGroup

	// Concurrent opens
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			svc.OpenChat(sessionID)
		}()
	}

	// Concurrent closes
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			svc.CloseSession(sessionID)
		}()
	}

	// Concurrent gets
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			svc.GetSession(sessionID)
		}()
	}

	wg.Wait()
	// If we get here without deadlock or panic, the test passes
}

// ============================================================================
// ListSessions tests
// ============================================================================

func TestListSessions_Empty_ReturnsEmptySlice(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	sessions := svc.ListSessions()

	if sessions == nil {
		t.Error("ListSessions should return empty slice, not nil")
	}
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestListSessions_WithSessions_ReturnsAll(t *testing.T) {
	host := newMockHost()
	mgr := newMockHandshakeManager()
	svc := NewChatService(host, mgr)

	// Create two sessions
	sessionID1 := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01}
	sessionID2 := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x02}

	sidHex1 := hex.EncodeToString(sessionID1)
	sidHex2 := hex.EncodeToString(sessionID2)

	mgr.addSession(sidHex1, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       peer.ID("peer-1"),
	})
	mgr.addSession(sidHex2, &mockHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: createTestSharedSecret(),
		peerID:       peer.ID("peer-2"),
	})

	svc.OpenChat(sessionID1)
	svc.OpenChat(sessionID2)

	sessions := svc.ListSessions()

	if len(sessions) != 2 {
		t.Errorf("expected 2 sessions, got %d", len(sessions))
	}
}

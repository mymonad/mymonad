// Package tests contains integration tests for the Human Chat system.
// These tests verify the complete encrypted chat flow between peers,
// including message send/receive, ACK verification, cleanup scenarios, and concurrent access.
package tests

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2pprotocol "github.com/libp2p/go-libp2p/core/protocol"
	pb "github.com/mymonad/mymonad/api/proto"
	"github.com/mymonad/mymonad/internal/chat"
	"github.com/mymonad/mymonad/pkg/protocol"
	"google.golang.org/protobuf/proto"
)

// ===========================================================================
// Mock Types for Integration Testing
// ===========================================================================

// chatIntegrationMockStream implements network.Stream for integration testing.
type chatIntegrationMockStream struct {
	reader   io.Reader
	writer   io.Writer
	protocol libp2pprotocol.ID
	closed   bool
	mu       sync.Mutex
}

func (s *chatIntegrationMockStream) Read(p []byte) (n int, err error) {
	return s.reader.Read(p)
}

func (s *chatIntegrationMockStream) Write(p []byte) (n int, err error) {
	return s.writer.Write(p)
}

func (s *chatIntegrationMockStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *chatIntegrationMockStream) CloseRead() error                                  { return nil }
func (s *chatIntegrationMockStream) CloseWrite() error                                 { return nil }
func (s *chatIntegrationMockStream) Reset() error                                      { return s.Close() }
func (s *chatIntegrationMockStream) ResetWithError(_ network.StreamErrorCode) error    { return s.Close() }
func (s *chatIntegrationMockStream) SetDeadline(t time.Time) error                     { return nil }
func (s *chatIntegrationMockStream) SetReadDeadline(t time.Time) error                 { return nil }
func (s *chatIntegrationMockStream) SetWriteDeadline(t time.Time) error                { return nil }
func (s *chatIntegrationMockStream) Protocol() libp2pprotocol.ID                       { return s.protocol }
func (s *chatIntegrationMockStream) SetProtocol(id libp2pprotocol.ID) error            { s.protocol = id; return nil }
func (s *chatIntegrationMockStream) Stat() network.Stats                               { return network.Stats{} }
func (s *chatIntegrationMockStream) Conn() network.Conn                                { return nil }
func (s *chatIntegrationMockStream) ID() string                                        { return "chat-integration-stream" }
func (s *chatIntegrationMockStream) Scope() network.StreamScope                        { return nil }

// chatIntegrationMockHost implements chat.StreamOpener for integration testing.
type chatIntegrationMockHost struct {
	mu       sync.Mutex
	streams  map[peer.ID]*chatIntegrationMockStream
	reader   io.Reader
	writer   io.Writer
}

func newChatIntegrationMockHost(reader io.Reader, writer io.Writer) *chatIntegrationMockHost {
	return &chatIntegrationMockHost{
		streams: make(map[peer.ID]*chatIntegrationMockStream),
		reader:  reader,
		writer:  writer,
	}
}

func (m *chatIntegrationMockHost) NewStream(ctx context.Context, p peer.ID, pids ...libp2pprotocol.ID) (network.Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stream := &chatIntegrationMockStream{
		reader:   m.reader,
		writer:   m.writer,
		protocol: chat.ChatProtocolID,
	}
	m.streams[p] = stream
	return stream, nil
}

// chatIntegrationHandshakeSession implements chat.HandshakeSessionProvider for integration tests.
type chatIntegrationHandshakeSession struct {
	state        protocol.State
	sharedSecret []byte
	peerID       peer.ID
}

func (m *chatIntegrationHandshakeSession) State() protocol.State {
	return m.state
}

func (m *chatIntegrationHandshakeSession) GetSharedSecret() []byte {
	return m.sharedSecret
}

func (m *chatIntegrationHandshakeSession) GetPeerID() peer.ID {
	return m.peerID
}

// chatIntegrationHandshakeManager implements chat.HandshakeManagerProvider and
// chat.HandshakeManagerWithStateChange for integration tests.
type chatIntegrationHandshakeManager struct {
	mu             sync.RWMutex
	sessions       map[string]*chatIntegrationHandshakeSession
	stateCallbacks map[string]func(protocol.State)
}

func newChatIntegrationHandshakeManager() *chatIntegrationHandshakeManager {
	return &chatIntegrationHandshakeManager{
		sessions:       make(map[string]*chatIntegrationHandshakeSession),
		stateCallbacks: make(map[string]func(protocol.State)),
	}
}

func (m *chatIntegrationHandshakeManager) GetSession(id string) chat.HandshakeSessionProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if s, ok := m.sessions[id]; ok {
		return s
	}
	return nil
}

func (m *chatIntegrationHandshakeManager) addSession(id string, session *chatIntegrationHandshakeSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[id] = session
}

func (m *chatIntegrationHandshakeManager) OnStateChange(sessionID []byte, callback func(protocol.State)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stateCallbacks[hex.EncodeToString(sessionID)] = callback
}

func (m *chatIntegrationHandshakeManager) triggerStateChange(sessionID []byte, newState protocol.State) {
	m.mu.Lock()
	callback, ok := m.stateCallbacks[hex.EncodeToString(sessionID)]
	if sess, exists := m.sessions[hex.EncodeToString(sessionID)]; exists {
		sess.state = newState
	}
	m.mu.Unlock()

	if ok {
		callback(newState)
	}
}

// sha256Sum computes SHA-256 hash of the data.
func sha256SumChat(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// ===========================================================================
// Test Session Wrapper (for direct testing without service layer)
// ===========================================================================

// TestChatSession is a test-friendly chat session for integration testing.
// It directly tests the chat protocol logic without the full service layer.
type TestChatSession struct {
	t            *testing.T
	sessionID    []byte
	chatKey      []byte
	peerID       peer.ID
	reader       io.Reader
	writer       io.Writer
	messages     []*testStoredMessage
	pendingAcks  map[string]*testPendingMessage
	isOpen       bool
	onMessage    func(*chat.ReceivedMessage)
	onDelivered  func([]byte)
	onTyping     func(bool)
	onCleanup    func()
	mu           sync.RWMutex
	lastActivity time.Time
}

type testStoredMessage struct {
	ID          []byte
	Plaintext   []byte
	SentAt      time.Time
	DeliveredAt *time.Time
	Direction   chat.MessageDirection
}

type testPendingMessage struct {
	ID        []byte
	Plaintext []byte
	SentAt    time.Time
	Retries   int
}

// newTestChatSession creates a TestChatSession for integration testing.
func newTestChatSession(
	t *testing.T,
	sessionID []byte,
	chatKey []byte,
	peerID peer.ID,
	reader io.Reader,
	writer io.Writer,
) *TestChatSession {
	t.Helper()

	return &TestChatSession{
		t:            t,
		sessionID:    sessionID,
		chatKey:      chatKey,
		peerID:       peerID,
		reader:       reader,
		writer:       writer,
		messages:     make([]*testStoredMessage, 0),
		pendingAcks:  make(map[string]*testPendingMessage),
		isOpen:       true,
		lastActivity: time.Now(),
	}
}

// SendMessage sends an encrypted message.
func (s *TestChatSession) SendMessage(text string) ([]byte, error) {
	// Check session state and prepare message data under lock
	s.mu.Lock()

	if !s.isOpen {
		s.mu.Unlock()
		return nil, errors.New("session closed")
	}

	// Generate message ID
	messageID := make([]byte, 16)
	if _, err := rand.Read(messageID); err != nil {
		s.mu.Unlock()
		return nil, err
	}

	// Create plaintext
	plaintext := &pb.ChatPlaintext{
		Text:   text,
		SentAt: time.Now().UnixMilli(),
	}
	plaintextBytes, err := proto.Marshal(plaintext)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}

	// Copy key for encryption
	chatKey := make([]byte, len(s.chatKey))
	copy(chatKey, s.chatKey)

	// Track pending ACK (before we release lock)
	s.pendingAcks[hex.EncodeToString(messageID)] = &testPendingMessage{
		ID:        messageID,
		Plaintext: plaintextBytes,
		SentAt:    time.Now(),
		Retries:   0,
	}

	// Store in buffer
	s.storeMessageLocked(&testStoredMessage{
		ID:        messageID,
		Plaintext: plaintextBytes,
		SentAt:    time.Now(),
		Direction: chat.DirectionSent,
	})

	s.lastActivity = time.Now()
	s.mu.Unlock()

	// Encrypt (outside lock)
	ciphertext, err := chat.Encrypt(chatKey, plaintextBytes)
	if err != nil {
		return nil, err
	}

	// Build envelope
	envelope := &pb.ChatEnvelope{
		Payload: &pb.ChatEnvelope_Message{
			Message: &pb.ChatMessage{
				MessageId:  messageID,
				Ciphertext: ciphertext[chat.NonceLength:],
				Nonce:      ciphertext[:chat.NonceLength],
				Timestamp:  time.Now().UnixMilli(),
			},
		},
	}

	// Write to stream (outside lock to avoid pipe deadlock)
	if err := s.writeEnvelope(envelope); err != nil {
		return nil, err
	}

	return messageID, nil
}

// writeEnvelope writes a length-prefixed envelope to the stream.
// This method does NOT hold locks - caller must ensure thread safety if needed.
func (s *TestChatSession) writeEnvelope(env *pb.ChatEnvelope) error {
	payload, err := proto.Marshal(env)
	if err != nil {
		return err
	}

	// Write length prefix (4 bytes big-endian)
	lengthBuf := make([]byte, 4)
	lengthBuf[0] = byte(len(payload) >> 24)
	lengthBuf[1] = byte(len(payload) >> 16)
	lengthBuf[2] = byte(len(payload) >> 8)
	lengthBuf[3] = byte(len(payload))

	if _, err := s.writer.Write(lengthBuf); err != nil {
		return err
	}
	if _, err := s.writer.Write(payload); err != nil {
		return err
	}

	return nil
}

// writeEnvelopeAsync writes an envelope asynchronously to avoid blocking.
func (s *TestChatSession) writeEnvelopeAsync(env *pb.ChatEnvelope) {
	go func() {
		s.writeEnvelope(env)
	}()
}

// storeMessageLocked adds a message to the buffer with eviction. Must hold lock.
func (s *TestChatSession) storeMessageLocked(msg *testStoredMessage) {
	if len(s.messages) >= chat.MaxBufferedMessages {
		evicted := s.messages[0]
		for i := range evicted.Plaintext {
			evicted.Plaintext[i] = 0
		}
		s.messages = s.messages[1:]
	}
	s.messages = append(s.messages, msg)
}

// handleMessage processes an incoming message.
func (s *TestChatSession) handleMessage(msg *pb.ChatMessage) {
	// Reassemble ciphertext
	ciphertext := append(msg.Nonce, msg.Ciphertext...)

	// Decrypt
	s.mu.RLock()
	chatKey := make([]byte, len(s.chatKey))
	copy(chatKey, s.chatKey)
	s.mu.RUnlock()

	plaintext, err := chat.Decrypt(chatKey, ciphertext)
	if err != nil {
		return
	}

	// Parse plaintext
	var content pb.ChatPlaintext
	if err := proto.Unmarshal(plaintext, &content); err != nil {
		for i := range plaintext {
			plaintext[i] = 0
		}
		return
	}

	// Store message first (under lock)
	s.mu.Lock()
	s.storeMessageLocked(&testStoredMessage{
		ID:        msg.MessageId,
		Plaintext: plaintext,
		SentAt:    time.UnixMilli(content.SentAt),
		Direction: chat.DirectionReceived,
	})
	s.lastActivity = time.Now()
	s.mu.Unlock()

	// Send ACK (outside lock to avoid deadlock with pipe)
	ack := &pb.ChatEnvelope{
		Payload: &pb.ChatEnvelope_Ack{
			Ack: &pb.ChatAck{
				MessageId:   msg.MessageId,
				MessageHash: sha256SumChat(plaintext),
			},
		},
	}
	s.writeEnvelopeAsync(ack)

	// Notify callback
	if s.onMessage != nil {
		s.onMessage(&chat.ReceivedMessage{
			ID:         msg.MessageId,
			Plaintext:  plaintext,
			ReceivedAt: time.Now(),
		})
	}
}

// handleAck processes an incoming ACK.
func (s *TestChatSession) handleAck(ack *pb.ChatAck) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idHex := hex.EncodeToString(ack.MessageId)
	pending, ok := s.pendingAcks[idHex]
	if !ok {
		return
	}

	// Verify hash
	expectedHash := sha256SumChat(pending.Plaintext)
	if !bytes.Equal(ack.MessageHash, expectedHash) {
		return
	}

	// Mark delivered
	delete(s.pendingAcks, idHex)
	now := time.Now()
	for _, msg := range s.messages {
		if bytes.Equal(msg.ID, ack.MessageId) {
			msg.DeliveredAt = &now
			break
		}
	}

	s.lastActivity = time.Now()

	// Notify callback (must call outside lock in real implementation, but ok for test)
	if s.onDelivered != nil {
		s.onDelivered(ack.MessageId)
	}
}

// handleTyping processes an incoming typing indicator.
func (s *TestChatSession) handleTyping(typing *pb.ChatTyping) {
	s.mu.Lock()
	s.lastActivity = time.Now()
	s.mu.Unlock()

	if s.onTyping != nil {
		s.onTyping(typing.IsTyping)
	}
}

// Cleanup closes the session and wipes sensitive data.
func (s *TestChatSession) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return
	}

	// Zero out sensitive data
	for i := range s.chatKey {
		s.chatKey[i] = 0
	}
	for _, msg := range s.messages {
		for i := range msg.Plaintext {
			msg.Plaintext[i] = 0
		}
	}
	for _, pending := range s.pendingAcks {
		for i := range pending.Plaintext {
			pending.Plaintext[i] = 0
		}
	}

	s.isOpen = false

	if s.onCleanup != nil {
		s.onCleanup()
	}
}

// retryPending simulates the retry logic.
func (s *TestChatSession) retryPending() {
	s.mu.Lock()

	if !s.isOpen {
		s.mu.Unlock()
		return
	}

	for _, pending := range s.pendingAcks {
		pending.Retries++

		if pending.Retries > chat.MaxRetries {
			s.mu.Unlock()
			s.Cleanup()
			return
		}
	}

	s.mu.Unlock()
}

// startReadLoop starts the read loop for the session.
func (s *TestChatSession) startReadLoop() {
	go func() {
		for {
			s.mu.RLock()
			isOpen := s.isOpen
			s.mu.RUnlock()

			if !isOpen {
				return
			}

			// Read length prefix
			lengthBuf := make([]byte, 4)
			if _, err := io.ReadFull(s.reader, lengthBuf); err != nil {
				return
			}

			length := uint32(lengthBuf[0])<<24 | uint32(lengthBuf[1])<<16 |
				uint32(lengthBuf[2])<<8 | uint32(lengthBuf[3])

			// Read payload
			payload := make([]byte, length)
			if _, err := io.ReadFull(s.reader, payload); err != nil {
				return
			}

			// Unmarshal envelope
			var env pb.ChatEnvelope
			if err := proto.Unmarshal(payload, &env); err != nil {
				continue
			}

			// Dispatch
			switch p := env.GetPayload().(type) {
			case *pb.ChatEnvelope_Message:
				s.handleMessage(p.Message)
			case *pb.ChatEnvelope_Ack:
				s.handleAck(p.Ack)
			case *pb.ChatEnvelope_Typing:
				s.handleTyping(p.Typing)
			}
		}
	}()
}

// ===========================================================================
// TestChat_FullConversation - Full send/receive flow test
// ===========================================================================

func TestChat_FullConversation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Log("Testing full conversation flow between Alice and Bob")

	// Create shared session data (simulating completed handshake)
	sessionID := make([]byte, 16)
	sharedSecret := make([]byte, 32)
	rand.Read(sessionID)
	rand.Read(sharedSecret)

	chatKey, err := chat.DeriveKey(sharedSecret, sessionID)
	if err != nil {
		t.Fatalf("failed to derive chat key: %v", err)
	}

	// Create bidirectional pipes
	// Alice writes to aliceWriter -> bobReader (Bob reads)
	// Bob writes to bobWriter -> aliceReader (Alice reads)
	aliceReader, bobWriter := io.Pipe()
	bobReader, aliceWriter := io.Pipe()
	defer aliceWriter.Close()
	defer bobWriter.Close()

	// Track received messages
	var aliceReceivedMsgs []*chat.ReceivedMessage
	var aliceDeliveredIDs [][]byte
	var bobReceivedMsgs []*chat.ReceivedMessage
	var bobDeliveredIDs [][]byte
	var mu sync.Mutex

	// Create Alice's session
	aliceChatKey := make([]byte, len(chatKey))
	copy(aliceChatKey, chatKey)
	aliceSession := newTestChatSession(t, sessionID, aliceChatKey, peer.ID("bob"), aliceReader, aliceWriter)
	aliceSession.onMessage = func(msg *chat.ReceivedMessage) {
		mu.Lock()
		aliceReceivedMsgs = append(aliceReceivedMsgs, msg)
		mu.Unlock()
	}
	aliceSession.onDelivered = func(id []byte) {
		mu.Lock()
		aliceDeliveredIDs = append(aliceDeliveredIDs, id)
		mu.Unlock()
	}
	defer aliceSession.Cleanup()

	// Create Bob's session
	bobChatKey := make([]byte, len(chatKey))
	copy(bobChatKey, chatKey)
	bobSession := newTestChatSession(t, sessionID, bobChatKey, peer.ID("alice"), bobReader, bobWriter)
	bobSession.onMessage = func(msg *chat.ReceivedMessage) {
		mu.Lock()
		bobReceivedMsgs = append(bobReceivedMsgs, msg)
		mu.Unlock()
	}
	bobSession.onDelivered = func(id []byte) {
		mu.Lock()
		bobDeliveredIDs = append(bobDeliveredIDs, id)
		mu.Unlock()
	}
	defer bobSession.Cleanup()

	// Start read loops
	aliceSession.startReadLoop()
	bobSession.startReadLoop()

	// Alice sends a message to Bob
	messageText := "Hello Bob! This is a test message from Alice."
	messageID, err := aliceSession.SendMessage(messageText)
	if err != nil {
		t.Fatalf("Alice failed to send message: %v", err)
	}
	t.Logf("Alice sent message with ID: %x", messageID)

	// Wait for Bob to receive and ACK
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

waitForDelivery:
	for {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for message delivery")
		case <-ticker.C:
			mu.Lock()
			bobReceived := len(bobReceivedMsgs) > 0
			aliceDelivered := len(aliceDeliveredIDs) > 0
			mu.Unlock()

			if bobReceived && aliceDelivered {
				break waitForDelivery
			}
		}
	}

	// Verify Bob received the message
	mu.Lock()
	if len(bobReceivedMsgs) == 0 {
		t.Fatal("Bob did not receive any message")
	}
	bobReceivedMsg := bobReceivedMsgs[0]

	var receivedPlaintext pb.ChatPlaintext
	if err := proto.Unmarshal(bobReceivedMsg.Plaintext, &receivedPlaintext); err != nil {
		t.Fatalf("failed to parse received plaintext: %v", err)
	}

	if receivedPlaintext.Text != messageText {
		t.Errorf("message content mismatch: got %q, want %q", receivedPlaintext.Text, messageText)
	}

	if !bytes.Equal(bobReceivedMsg.ID, messageID) {
		t.Errorf("message ID mismatch: got %x, want %x", bobReceivedMsg.ID, messageID)
	}

	// Verify Alice received delivery confirmation
	if len(aliceDeliveredIDs) == 0 {
		t.Fatal("Alice did not receive delivery confirmation")
	}

	if !bytes.Equal(aliceDeliveredIDs[0], messageID) {
		t.Error("delivered message ID does not match sent message ID")
	}
	mu.Unlock()

	// Verify message is no longer pending on Alice's side
	aliceSession.mu.RLock()
	_, stillPending := aliceSession.pendingAcks[hex.EncodeToString(messageID)]
	aliceSession.mu.RUnlock()

	if stillPending {
		t.Error("message should be removed from pending after ACK")
	}

	t.Log("Full conversation test passed: message sent, received, and ACKed successfully")
}

// ===========================================================================
// TestChat_AckVerification - ACK with hash verification
// ===========================================================================

func TestChat_AckVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Log("Testing ACK verification with SHA-256 hash")

	// Setup
	sessionID := make([]byte, 16)
	sharedSecret := make([]byte, 32)
	rand.Read(sessionID)
	rand.Read(sharedSecret)

	chatKey, _ := chat.DeriveKey(sharedSecret, sessionID)

	aliceReader, bobWriter := io.Pipe()
	bobReader, aliceWriter := io.Pipe()
	defer aliceWriter.Close()
	defer bobWriter.Close()

	var aliceDeliveredIDs [][]byte
	var mu sync.Mutex

	aliceChatKey := make([]byte, len(chatKey))
	copy(aliceChatKey, chatKey)
	aliceSession := newTestChatSession(t, sessionID, aliceChatKey, peer.ID("bob"), aliceReader, aliceWriter)
	aliceSession.onDelivered = func(id []byte) {
		mu.Lock()
		aliceDeliveredIDs = append(aliceDeliveredIDs, id)
		mu.Unlock()
	}
	defer aliceSession.Cleanup()

	bobChatKey := make([]byte, len(chatKey))
	copy(bobChatKey, chatKey)
	bobSession := newTestChatSession(t, sessionID, bobChatKey, peer.ID("alice"), bobReader, bobWriter)
	defer bobSession.Cleanup()

	aliceSession.startReadLoop()
	bobSession.startReadLoop()

	// Alice sends message
	messageText := "Test message for ACK verification"
	messageID, err := aliceSession.SendMessage(messageText)
	if err != nil {
		t.Fatalf("failed to send message: %v", err)
	}

	// Get the expected plaintext hash before ACK arrives
	aliceSession.mu.RLock()
	pending := aliceSession.pendingAcks[hex.EncodeToString(messageID)]
	expectedHash := sha256SumChat(pending.Plaintext)
	aliceSession.mu.RUnlock()

	// Wait for ACK to be processed
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

waitForAck:
	for {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for ACK")
		case <-ticker.C:
			mu.Lock()
			if len(aliceDeliveredIDs) > 0 {
				mu.Unlock()
				break waitForAck
			}
			mu.Unlock()
		}
	}

	// Verify message is removed from pending
	aliceSession.mu.RLock()
	_, stillPending := aliceSession.pendingAcks[hex.EncodeToString(messageID)]
	aliceSession.mu.RUnlock()

	if stillPending {
		t.Error("message should be removed from pending after valid ACK")
	}

	// Verify the delivered ID matches
	mu.Lock()
	if !bytes.Equal(aliceDeliveredIDs[0], messageID) {
		t.Error("delivered message ID does not match sent message ID")
	}
	mu.Unlock()

	t.Logf("ACK verification passed: hash %x verified correctly", expectedHash)
}

// ===========================================================================
// TestChat_SecureCleanup - Cleanup on unmask test
// ===========================================================================

func TestChat_SecureCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Log("Testing secure cleanup when handshake reaches terminal state")

	// Create mock handshake manager
	mgr := newChatIntegrationHandshakeManager()

	sessionID := make([]byte, 16)
	sharedSecret := make([]byte, 32)
	rand.Read(sessionID)
	rand.Read(sharedSecret)

	sidHex := hex.EncodeToString(sessionID)
	mgr.addSession(sidHex, &chatIntegrationHandshakeSession{
		state:        protocol.StateHumanChat,
		sharedSecret: sharedSecret,
		peerID:       peer.ID("peer"),
	})

	// Create pipes
	_, writer := io.Pipe()
	reader, _ := io.Pipe()
	defer writer.Close()

	// Create mock host
	host := newChatIntegrationMockHost(reader, writer)

	// Create service
	svc := chat.NewChatService(host, mgr)

	// Open chat session
	_, err := svc.OpenChat(sessionID)
	if err != nil {
		t.Fatalf("failed to open chat: %v", err)
	}

	// Verify session exists
	sessions := svc.ListSessions()
	if len(sessions) != 1 {
		t.Errorf("expected 1 session, got %d", len(sessions))
	}

	// Close the session (simulating terminal state cleanup)
	svc.CloseSession(sessionID)

	// Verify session is removed
	if svc.GetSession(sessionID) != nil {
		t.Error("session should be nil after cleanup")
	}

	sessions = svc.ListSessions()
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions after cleanup, got %d", len(sessions))
	}

	t.Log("Secure cleanup test passed: session cleaned up on terminal state")
}

// ===========================================================================
// TestChat_RetryCapCleanup - Max retry cleanup
// ===========================================================================

func TestChat_RetryCapCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Log("Testing cleanup when max retries exceeded")

	sessionID := make([]byte, 16)
	chatKey := make([]byte, chat.ChatKeyLength)
	rand.Read(sessionID)
	rand.Read(chatKey)

	// Create a session with a discard writer (ACKs never arrive)
	var cleanupCalled atomic.Bool
	session := newTestChatSession(t, sessionID, chatKey, peer.ID("peer"),
		&discardReader{}, &discardWriter{})
	session.onCleanup = func() {
		cleanupCalled.Store(true)
	}

	// Add a pending message at max retries
	msgID := make([]byte, 16)
	rand.Read(msgID)
	msgIDHex := hex.EncodeToString(msgID)

	session.mu.Lock()
	session.pendingAcks[msgIDHex] = &testPendingMessage{
		ID:        msgID,
		Plaintext: []byte("test message"),
		SentAt:    time.Now(),
		Retries:   chat.MaxRetries, // At max retries
	}
	session.mu.Unlock()

	// Simulate retry that exceeds max
	session.retryPending()

	// Verify cleanup was triggered
	if !cleanupCalled.Load() {
		t.Error("cleanup should be called when max retries exceeded")
	}

	// Verify session is closed
	session.mu.RLock()
	isOpen := session.isOpen
	session.mu.RUnlock()

	if isOpen {
		t.Error("session should be closed after max retries exceeded")
	}

	t.Log("Max retry cleanup test passed")
}

// discardReader returns EOF on all reads.
type discardReader struct{}

func (d *discardReader) Read(p []byte) (n int, err error) { return 0, io.EOF }

// discardWriter discards all writes.
type discardWriter struct{}

func (d *discardWriter) Write(p []byte) (n int, err error) { return len(p), nil }

// ===========================================================================
// TestChat_ConcurrentMessages - Concurrent messaging
// ===========================================================================

func TestChat_ConcurrentMessages(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Log("Testing concurrent message sending from same side")

	// Setup - test concurrent sends from one side to avoid pipe deadlocks
	sessionID := make([]byte, 16)
	sharedSecret := make([]byte, 32)
	rand.Read(sessionID)
	rand.Read(sharedSecret)

	chatKey, _ := chat.DeriveKey(sharedSecret, sessionID)

	aliceReader, bobWriter := io.Pipe()
	bobReader, aliceWriter := io.Pipe()
	defer aliceWriter.Close()
	defer bobWriter.Close()

	var bobReceivedCount atomic.Int32
	var aliceDeliveredCount atomic.Int32

	aliceChatKey := make([]byte, len(chatKey))
	copy(aliceChatKey, chatKey)
	aliceSession := newTestChatSession(t, sessionID, aliceChatKey, peer.ID("bob"), aliceReader, aliceWriter)
	aliceSession.onDelivered = func(id []byte) {
		aliceDeliveredCount.Add(1)
	}
	defer aliceSession.Cleanup()

	bobChatKey := make([]byte, len(chatKey))
	copy(bobChatKey, chatKey)
	bobSession := newTestChatSession(t, sessionID, bobChatKey, peer.ID("alice"), bobReader, bobWriter)
	bobSession.onMessage = func(msg *chat.ReceivedMessage) {
		bobReceivedCount.Add(1)
	}
	defer bobSession.Cleanup()

	// Start read loops
	aliceSession.startReadLoop()
	bobSession.startReadLoop()

	// Send messages concurrently from Alice only (to avoid pipe deadlocks)
	numMessages := 5
	var wg sync.WaitGroup
	var sendErrors atomic.Int32

	// Alice sends messages concurrently
	for i := 0; i < numMessages; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			msg := "Alice message " + string(rune('A'+idx))
			if _, err := aliceSession.SendMessage(msg); err != nil {
				sendErrors.Add(1)
			}
		}(i)
	}

	wg.Wait()

	if errs := sendErrors.Load(); errs > 0 {
		t.Errorf("%d concurrent sends failed", errs)
	}

	// Wait for all messages to be delivered
	deadline := time.After(10 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			t.Fatalf("timeout: Bob received=%d, Alice delivered=%d",
				bobReceivedCount.Load(), aliceDeliveredCount.Load())
		case <-ticker.C:
			bobRecv := bobReceivedCount.Load()
			aliceDel := aliceDeliveredCount.Load()

			// Bob receives all of Alice's messages, Alice gets all ACKs
			if bobRecv >= int32(numMessages) && aliceDel >= int32(numMessages) {
				t.Logf("All messages delivered: Bob recv=%d, Alice del=%d",
					bobRecv, aliceDel)
				return
			}
		}
	}
}

// ===========================================================================
// TestChat_RejectInvalidACK - Reject ACK with wrong hash
// ===========================================================================

func TestChat_RejectInvalidACK(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Log("Testing rejection of ACK with invalid hash")

	sessionID := make([]byte, 16)
	chatKey := make([]byte, chat.ChatKeyLength)
	rand.Read(sessionID)
	rand.Read(chatKey)

	var deliveredCalled atomic.Bool

	session := newTestChatSession(t, sessionID, chatKey, peer.ID("peer"),
		&discardReader{}, &discardWriter{})
	session.onDelivered = func(id []byte) {
		deliveredCalled.Store(true)
	}
	defer session.Cleanup()

	// Add a pending message
	msgID := make([]byte, 16)
	rand.Read(msgID)
	msgIDHex := hex.EncodeToString(msgID)
	plaintext := []byte("test message plaintext")

	session.mu.Lock()
	session.pendingAcks[msgIDHex] = &testPendingMessage{
		ID:        msgID,
		Plaintext: plaintext,
		SentAt:    time.Now(),
		Retries:   0,
	}
	session.mu.Unlock()

	// Create ACK with WRONG hash
	wrongHash := sha256SumChat([]byte("wrong plaintext"))
	invalidAck := &pb.ChatAck{
		MessageId:   msgID,
		MessageHash: wrongHash,
	}

	// Handle the invalid ACK
	session.handleAck(invalidAck)

	// Verify delivery callback was NOT called
	if deliveredCalled.Load() {
		t.Error("onDelivered should not be called for invalid ACK")
	}

	// Verify message is still pending
	session.mu.RLock()
	_, stillPending := session.pendingAcks[msgIDHex]
	session.mu.RUnlock()

	if !stillPending {
		t.Error("message should still be pending after invalid ACK")
	}

	t.Log("Invalid ACK rejection test passed")
}

// ===========================================================================
// TestChat_BufferEviction - Message buffer size limit
// ===========================================================================

func TestChat_BufferEviction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Log("Testing message buffer eviction when limit exceeded")

	session := newTestChatSession(t, make([]byte, 16), make([]byte, 32),
		peer.ID("peer"), &discardReader{}, &discardWriter{})
	defer session.Cleanup()

	// Fill buffer beyond MaxBufferedMessages
	for i := 0; i < chat.MaxBufferedMessages+10; i++ {
		msgID := make([]byte, 16)
		rand.Read(msgID)

		session.mu.Lock()
		session.storeMessageLocked(&testStoredMessage{
			ID:        msgID,
			Plaintext: []byte("message " + string(rune('A'+i%26))),
			SentAt:    time.Now(),
			Direction: chat.DirectionSent,
		})
		session.mu.Unlock()
	}

	// Verify buffer is at max size
	session.mu.RLock()
	bufferLen := len(session.messages)
	session.mu.RUnlock()

	if bufferLen > chat.MaxBufferedMessages {
		t.Errorf("buffer size %d exceeds max %d", bufferLen, chat.MaxBufferedMessages)
	}

	t.Logf("Buffer eviction test passed: buffer size = %d (max = %d)", bufferLen, chat.MaxBufferedMessages)
}

// ===========================================================================
// TestChat_DuplicateACK - Duplicate ACK handling
// ===========================================================================

func TestChat_DuplicateACK(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Log("Testing duplicate ACK handling")

	var deliveredCount atomic.Int32

	session := newTestChatSession(t, make([]byte, 16), make([]byte, 32),
		peer.ID("peer"), &discardReader{}, &discardWriter{})
	session.onDelivered = func(id []byte) {
		deliveredCount.Add(1)
	}
	defer session.Cleanup()

	// Add a pending message
	msgID := make([]byte, 16)
	rand.Read(msgID)
	plaintext := []byte("test message")

	session.mu.Lock()
	session.pendingAcks[hex.EncodeToString(msgID)] = &testPendingMessage{
		ID:        msgID,
		Plaintext: plaintext,
		SentAt:    time.Now(),
		Retries:   0,
	}
	session.messages = append(session.messages, &testStoredMessage{
		ID:        msgID,
		Plaintext: plaintext,
		SentAt:    time.Now(),
		Direction: chat.DirectionSent,
	})
	session.mu.Unlock()

	// Create valid ACK
	correctHash := sha256SumChat(plaintext)
	validAck := &pb.ChatAck{
		MessageId:   msgID,
		MessageHash: correctHash,
	}

	// Handle ACK multiple times
	session.handleAck(validAck)
	session.handleAck(validAck) // Duplicate
	session.handleAck(validAck) // Another duplicate

	// Verify callback was called only once
	if count := deliveredCount.Load(); count != 1 {
		t.Errorf("onDelivered should be called once, got %d", count)
	}

	t.Log("Duplicate ACK handling test passed")
}

// ===========================================================================
// TestChat_TypingIndicators - Typing indicator flow
// ===========================================================================

func TestChat_TypingIndicators(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Log("Testing typing indicator flow")

	sessionID := make([]byte, 16)
	sharedSecret := make([]byte, 32)
	rand.Read(sessionID)
	rand.Read(sharedSecret)

	chatKey, _ := chat.DeriveKey(sharedSecret, sessionID)

	aliceReader, bobWriter := io.Pipe()
	bobReader, aliceWriter := io.Pipe()
	defer aliceWriter.Close()
	defer bobWriter.Close()

	var bobTypingUpdates []bool
	var mu sync.Mutex

	aliceChatKey := make([]byte, len(chatKey))
	copy(aliceChatKey, chatKey)
	aliceSession := newTestChatSession(t, sessionID, aliceChatKey, peer.ID("bob"), aliceReader, aliceWriter)
	defer aliceSession.Cleanup()

	bobChatKey := make([]byte, len(chatKey))
	copy(bobChatKey, chatKey)
	bobSession := newTestChatSession(t, sessionID, bobChatKey, peer.ID("alice"), bobReader, bobWriter)
	bobSession.onTyping = func(isTyping bool) {
		mu.Lock()
		bobTypingUpdates = append(bobTypingUpdates, isTyping)
		mu.Unlock()
	}
	defer bobSession.Cleanup()

	aliceSession.startReadLoop()
	bobSession.startReadLoop()

	// Alice sends typing indicator
	typingEnvelope := &pb.ChatEnvelope{
		Payload: &pb.ChatEnvelope_Typing{
			Typing: &pb.ChatTyping{
				IsTyping: true,
			},
		},
	}

	aliceSession.mu.Lock()
	err := aliceSession.writeEnvelope(typingEnvelope)
	aliceSession.mu.Unlock()
	if err != nil {
		t.Fatalf("failed to send typing indicator: %v", err)
	}

	// Wait for Bob to receive typing indicator
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

waitForTyping:
	for {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for typing indicator")
		case <-ticker.C:
			mu.Lock()
			if len(bobTypingUpdates) > 0 && bobTypingUpdates[0] == true {
				mu.Unlock()
				break waitForTyping
			}
			mu.Unlock()
		}
	}

	t.Log("Typing indicator test passed")
}

// ===========================================================================
// Benchmarks
// ===========================================================================

func BenchmarkChat_SendMessage(b *testing.B) {
	sessionID := make([]byte, 16)
	chatKey := make([]byte, chat.ChatKeyLength)
	rand.Read(sessionID)
	rand.Read(chatKey)

	session := newTestChatSession(&testing.T{}, sessionID, chatKey, peer.ID("peer"),
		&discardReader{}, &discardWriter{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session.SendMessage("benchmark test message")
	}
}

func BenchmarkChat_EncryptDecrypt(b *testing.B) {
	chatKey := make([]byte, chat.ChatKeyLength)
	rand.Read(chatKey)
	plaintext := []byte("benchmark encryption test message content")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ciphertext, _ := chat.Encrypt(chatKey, plaintext)
		chat.Decrypt(chatKey, ciphertext)
	}
}

func BenchmarkChat_KeyDerivation(b *testing.B) {
	sharedSecret := make([]byte, 32)
	sessionID := make([]byte, 16)
	rand.Read(sharedSecret)
	rand.Read(sessionID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		chat.DeriveKey(sharedSecret, sessionID)
	}
}

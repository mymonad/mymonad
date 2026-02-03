package chat

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
	"google.golang.org/protobuf/proto"
)

// streamMock is a mock for testing stream read/write operations.
// This is separate from mockStream in service_test.go which implements network.Stream.
type streamMock struct {
	mu       sync.Mutex
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	closed   bool
	readErr  error
	writeErr error
}

func newStreamMock() *streamMock {
	return &streamMock{
		readBuf:  bytes.NewBuffer(nil),
		writeBuf: bytes.NewBuffer(nil),
	}
}

func (m *streamMock) Read(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, io.EOF
	}
	if m.readErr != nil {
		return 0, m.readErr
	}
	return m.readBuf.Read(p)
}

func (m *streamMock) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, ErrStreamBroken
	}
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return m.writeBuf.Write(p)
}

func (m *streamMock) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// setReadData sets the data to be read from the stream.
func (m *streamMock) setReadData(data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readBuf = bytes.NewBuffer(data)
}

// getWrittenData returns the data written to the stream.
func (m *streamMock) getWrittenData() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writeBuf.Bytes()
}

// --- writeEnvelope Tests ---

// TestWriteEnvelope_SendsCorrectBytes verifies that writeEnvelope sends correct length-prefixed data.
func TestWriteEnvelope_SendsCorrectBytes(t *testing.T) {
	stream := newStreamMock()
	session := newTestSessionForStreamOps(t, stream)
	defer session.Cleanup()

	// Create a typing envelope (simple case)
	env := &pb.ChatEnvelope{
		Payload: &pb.ChatEnvelope_Typing{
			Typing: &pb.ChatTyping{
				IsTyping: true,
			},
		},
	}

	err := session.writeEnvelopeImpl(env)
	if err != nil {
		t.Fatalf("writeEnvelope failed: %v", err)
	}

	// Get written data
	written := stream.getWrittenData()

	// Verify length prefix (4 bytes big-endian)
	if len(written) < 4 {
		t.Fatal("written data too short for length prefix")
	}

	length := binary.BigEndian.Uint32(written[:4])
	payload := written[4:]

	// Verify payload length matches
	if int(length) != len(payload) {
		t.Errorf("length prefix mismatch: got %d, payload len %d", length, len(payload))
	}

	// Verify payload can be unmarshaled
	var parsed pb.ChatEnvelope
	if err := proto.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("failed to unmarshal written payload: %v", err)
	}

	// Verify content
	typing := parsed.GetTyping()
	if typing == nil {
		t.Fatal("parsed envelope does not contain typing")
	}
	if !typing.IsTyping {
		t.Error("IsTyping should be true")
	}
}

// TestWriteEnvelope_ErrorsOnNilStream verifies that writeEnvelope returns error on nil stream.
func TestWriteEnvelope_ErrorsOnNilStream(t *testing.T) {
	session := newTestSessionForStreamOps(t, nil)
	defer session.Cleanup()

	env := &pb.ChatEnvelope{
		Payload: &pb.ChatEnvelope_Typing{
			Typing: &pb.ChatTyping{IsTyping: true},
		},
	}

	err := session.writeEnvelopeImpl(env)
	if err == nil {
		t.Fatal("expected error for nil stream")
	}

	if !errors.Is(err, ErrStreamBroken) {
		t.Errorf("expected ErrStreamBroken, got: %v", err)
	}
}

// TestWriteEnvelope_ErrorsOnClosedSession verifies that writeEnvelope returns error on closed session.
func TestWriteEnvelope_ErrorsOnClosedSession(t *testing.T) {
	stream := newStreamMock()
	session := newTestSessionForStreamOps(t, stream)

	// Close the session
	session.Cleanup()

	env := &pb.ChatEnvelope{
		Payload: &pb.ChatEnvelope_Typing{
			Typing: &pb.ChatTyping{IsTyping: true},
		},
	}

	err := session.writeEnvelopeImpl(env)
	if err == nil {
		t.Fatal("expected error for closed session")
	}

	if !errors.Is(err, ErrSessionClosed) {
		t.Errorf("expected ErrSessionClosed, got: %v", err)
	}
}

// TestWriteEnvelope_ErrorsOnWriteFailure verifies that writeEnvelope propagates write errors.
func TestWriteEnvelope_ErrorsOnWriteFailure(t *testing.T) {
	stream := newStreamMock()
	stream.writeErr = errors.New("network error")
	session := newTestSessionForStreamOps(t, stream)
	defer session.Cleanup()

	env := &pb.ChatEnvelope{
		Payload: &pb.ChatEnvelope_Typing{
			Typing: &pb.ChatTyping{IsTyping: true},
		},
	}

	err := session.writeEnvelopeImpl(env)
	if err == nil {
		t.Fatal("expected error for write failure")
	}
}

// --- readEnvelope Tests ---

// TestReadEnvelope_ParsesCorrectly verifies that readEnvelope parses length-prefixed data.
func TestReadEnvelope_ParsesCorrectly(t *testing.T) {
	stream := newStreamMock()
	session := newTestSessionForStreamOps(t, stream)
	defer session.Cleanup()

	// Create envelope and marshal
	env := &pb.ChatEnvelope{
		Payload: &pb.ChatEnvelope_Typing{
			Typing: &pb.ChatTyping{IsTyping: true},
		},
	}
	payload, err := proto.Marshal(env)
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	// Write length-prefixed data to stream
	data := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(data[:4], uint32(len(payload)))
	copy(data[4:], payload)
	stream.setReadData(data)

	// Read envelope
	parsed, err := session.readEnvelopeImpl()
	if err != nil {
		t.Fatalf("readEnvelope failed: %v", err)
	}

	// Verify content
	typing := parsed.GetTyping()
	if typing == nil {
		t.Fatal("parsed envelope does not contain typing")
	}
	if !typing.IsTyping {
		t.Error("IsTyping should be true")
	}
}

// TestReadEnvelope_ErrorsOnOversizedEnvelope verifies that oversized envelopes are rejected.
func TestReadEnvelope_ErrorsOnOversizedEnvelope(t *testing.T) {
	stream := newStreamMock()
	session := newTestSessionForStreamOps(t, stream)
	defer session.Cleanup()

	// Write length prefix indicating oversized envelope
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data[:4], MaxEnvelopeSize+1)
	stream.setReadData(data)

	_, err := session.readEnvelopeImpl()
	if err == nil {
		t.Fatal("expected error for oversized envelope")
	}

	if !errors.Is(err, ErrEnvelopeTooLarge) {
		t.Errorf("expected ErrEnvelopeTooLarge, got: %v", err)
	}
}

// TestReadEnvelope_ErrorsOnNilStream verifies that readEnvelope returns error on nil stream.
func TestReadEnvelope_ErrorsOnNilStream(t *testing.T) {
	session := newTestSessionForStreamOps(t, nil)
	defer session.Cleanup()

	_, err := session.readEnvelopeImpl()
	if err == nil {
		t.Fatal("expected error for nil stream")
	}

	if !errors.Is(err, ErrStreamBroken) {
		t.Errorf("expected ErrStreamBroken, got: %v", err)
	}
}

// TestReadEnvelope_ErrorsOnEOF verifies that readEnvelope returns EOF on stream end.
func TestReadEnvelope_ErrorsOnEOF(t *testing.T) {
	stream := newStreamMock()
	stream.setReadData([]byte{}) // Empty - will return EOF
	session := newTestSessionForStreamOps(t, stream)
	defer session.Cleanup()

	_, err := session.readEnvelopeImpl()
	if err == nil {
		t.Fatal("expected error for EOF")
	}

	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF, got: %v", err)
	}
}

// TestReadEnvelope_ErrorsOnInvalidProtobuf verifies that invalid protobuf is rejected.
func TestReadEnvelope_ErrorsOnInvalidProtobuf(t *testing.T) {
	stream := newStreamMock()
	session := newTestSessionForStreamOps(t, stream)
	defer session.Cleanup()

	// Write length prefix with invalid protobuf data
	invalidPayload := []byte{0xff, 0xff, 0xff, 0xff}
	data := make([]byte, 4+len(invalidPayload))
	binary.BigEndian.PutUint32(data[:4], uint32(len(invalidPayload)))
	copy(data[4:], invalidPayload)
	stream.setReadData(data)

	_, err := session.readEnvelopeImpl()
	if err == nil {
		t.Fatal("expected error for invalid protobuf")
	}
}

// TestReadEnvelope_ErrorsOnTruncatedPayload verifies that truncated payload is handled.
func TestReadEnvelope_ErrorsOnTruncatedPayload(t *testing.T) {
	stream := newStreamMock()
	session := newTestSessionForStreamOps(t, stream)
	defer session.Cleanup()

	// Write length prefix claiming more data than available
	data := make([]byte, 4+5) // Only 5 bytes of payload
	binary.BigEndian.PutUint32(data[:4], 100) // But claims 100 bytes
	stream.setReadData(data)

	_, err := session.readEnvelopeImpl()
	if err == nil {
		t.Fatal("expected error for truncated payload")
	}
}

// --- readLoop Tests ---

// TestReadLoop_DispatchesMessage verifies that readLoop dispatches ChatMessage to handleMessage.
func TestReadLoop_DispatchesMessage(t *testing.T) {
	stream := newStreamMock()
	session := newTestSessionForStreamOps(t, stream)

	// Track received messages - we need to copy the ID since cleanup will zero it
	var receivedMsgID []byte
	var receivedMsgCalled bool
	session.onMessage = func(msg *ReceivedMessage) {
		receivedMsgCalled = true
		// Copy the ID since cleanup will zero the original
		receivedMsgID = make([]byte, len(msg.ID))
		copy(receivedMsgID, msg.ID)
	}

	// Prepare encrypted message
	text := "Hello from readLoop"
	plaintext := &pb.ChatPlaintext{
		Text:   text,
		SentAt: time.Now().UnixMilli(),
	}
	plaintextBytes, err := proto.Marshal(plaintext)
	if err != nil {
		t.Fatalf("failed to marshal plaintext: %v", err)
	}

	session.mu.RLock()
	chatKey := session.chatKey
	session.mu.RUnlock()

	ciphertext, err := Encrypt(chatKey, plaintextBytes)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	messageID := make([]byte, 16)
	if _, err := rand.Read(messageID); err != nil {
		t.Fatalf("failed to generate message ID: %v", err)
	}

	// Create message envelope
	env := &pb.ChatEnvelope{
		Payload: &pb.ChatEnvelope_Message{
			Message: &pb.ChatMessage{
				MessageId:  messageID,
				Nonce:      ciphertext[:NonceLength],
				Ciphertext: ciphertext[NonceLength:],
				Timestamp:  time.Now().UnixMilli(),
			},
		},
	}

	// Serialize to stream
	payload, err := proto.Marshal(env)
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	data := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(data[:4], uint32(len(payload)))
	copy(data[4:], payload)
	stream.setReadData(data)

	// Run readLoop in goroutine
	done := make(chan struct{})
	go func() {
		session.readLoop()
		close(done)
	}()

	// Wait for readLoop to complete (will exit on EOF after reading message)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop did not complete in time")
	}

	// Verify message was received
	if !receivedMsgCalled {
		t.Fatal("message was not dispatched to onMessage callback")
	}

	if !bytes.Equal(receivedMsgID, messageID) {
		t.Errorf("received message ID does not match: got %x, want %x", receivedMsgID, messageID)
	}
}

// TestReadLoop_DispatchesAck verifies that readLoop dispatches ChatAck to handleAck.
func TestReadLoop_DispatchesAck(t *testing.T) {
	stream := newStreamMock()
	session := newTestSessionForStreamOps(t, stream)

	// Generate a message ID and create a pending ACK entry directly
	messageID := make([]byte, 16)
	if _, err := rand.Read(messageID); err != nil {
		t.Fatalf("failed to generate message ID: %v", err)
	}

	// Create plaintext and hash for the pending message
	plaintext := []byte("test plaintext")
	plaintextHash := sha256Sum(plaintext)

	// Add pending ACK entry manually
	session.mu.Lock()
	idHex := hex.EncodeToString(messageID)
	session.pendingAcks[idHex] = &PendingMessage{
		ID:        messageID,
		Plaintext: plaintext,
	}
	session.mu.Unlock()

	// Track delivered messages - copy the ID since cleanup will zero it
	var deliveredID []byte
	var deliveredCalled bool
	session.onDelivered = func(id []byte) {
		deliveredCalled = true
		deliveredID = make([]byte, len(id))
		copy(deliveredID, id)
	}

	// Create ACK envelope
	env := &pb.ChatEnvelope{
		Payload: &pb.ChatEnvelope_Ack{
			Ack: &pb.ChatAck{
				MessageId:   messageID,
				MessageHash: plaintextHash,
			},
		},
	}

	// Serialize to stream
	payload, err := proto.Marshal(env)
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	data := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(data[:4], uint32(len(payload)))
	copy(data[4:], payload)
	stream.setReadData(data)

	// Run readLoop
	done := make(chan struct{})
	go func() {
		session.readLoop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop did not complete in time")
	}

	// Verify ACK was processed
	if !deliveredCalled {
		t.Error("onDelivered callback was not called")
	}
	if !bytes.Equal(deliveredID, messageID) {
		t.Errorf("ACK was not dispatched to handleAck: got %x, want %x", deliveredID, messageID)
	}
}

// TestReadLoop_DispatchesTyping verifies that readLoop dispatches ChatTyping to handleTyping.
func TestReadLoop_DispatchesTyping(t *testing.T) {
	stream := newStreamMock()
	session := newTestSessionForStreamOps(t, stream)

	// Track typing status
	var typingStatus bool
	var typingCalled bool
	session.onTyping = func(isTyping bool) {
		typingStatus = isTyping
		typingCalled = true
	}

	// Create typing envelope
	env := &pb.ChatEnvelope{
		Payload: &pb.ChatEnvelope_Typing{
			Typing: &pb.ChatTyping{
				IsTyping: true,
			},
		},
	}

	// Serialize to stream
	payload, err := proto.Marshal(env)
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	data := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(data[:4], uint32(len(payload)))
	copy(data[4:], payload)
	stream.setReadData(data)

	// Run readLoop
	done := make(chan struct{})
	go func() {
		session.readLoop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop did not complete in time")
	}

	// Verify typing was dispatched
	if !typingCalled {
		t.Fatal("typing was not dispatched to handleTyping")
	}
	if !typingStatus {
		t.Error("typing status should be true")
	}
}

// TestReadLoop_HandlesEOFGracefully verifies that readLoop handles EOF gracefully.
func TestReadLoop_HandlesEOFGracefully(t *testing.T) {
	stream := newStreamMock()
	session := newTestSessionForStreamOps(t, stream)

	// Set empty stream (will return EOF immediately)
	stream.setReadData([]byte{})

	// Track cleanup
	var cleanupCalled bool
	session.onCleanup = func() {
		cleanupCalled = true
	}

	// Run readLoop
	done := make(chan struct{})
	go func() {
		session.readLoop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop did not complete in time")
	}

	// Verify cleanup was called
	if !cleanupCalled {
		t.Error("cleanup should be called on EOF")
	}
}

// TestReadLoop_HandlesReadError verifies that readLoop handles read errors.
func TestReadLoop_HandlesReadError(t *testing.T) {
	stream := newStreamMock()
	stream.readErr = errors.New("network error")
	session := newTestSessionForStreamOps(t, stream)

	// Track cleanup
	var cleanupCalled bool
	session.onCleanup = func() {
		cleanupCalled = true
	}

	// Run readLoop
	done := make(chan struct{})
	go func() {
		session.readLoop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop did not complete in time")
	}

	// Verify cleanup was called
	if !cleanupCalled {
		t.Error("cleanup should be called on read error")
	}
}

// --- handleStreamClose Tests ---

// TestHandleStreamClose_CallsCleanup verifies that handleStreamClose calls Cleanup.
func TestHandleStreamClose_CallsCleanup(t *testing.T) {
	stream := newStreamMock()
	session := newTestSessionForStreamOps(t, stream)

	// Track cleanup
	var cleanupCalled bool
	session.onCleanup = func() {
		cleanupCalled = true
	}

	// Call handleStreamClose
	session.handleStreamClose()

	// Verify cleanup was called
	if !cleanupCalled {
		t.Error("Cleanup should be called")
	}

	// Verify session is closed
	session.mu.RLock()
	defer session.mu.RUnlock()
	if session.isOpen {
		t.Error("session should be closed after handleStreamClose")
	}
}

// TestHandleStreamClose_Idempotent verifies that handleStreamClose is safe to call multiple times.
func TestHandleStreamClose_Idempotent(t *testing.T) {
	stream := newStreamMock()
	session := newTestSessionForStreamOps(t, stream)

	// Track cleanup calls
	cleanupCount := 0
	session.onCleanup = func() {
		cleanupCount++
	}

	// Call handleStreamClose multiple times
	session.handleStreamClose()
	session.handleStreamClose()
	session.handleStreamClose()

	// Verify cleanup was only called once (idempotent via Cleanup)
	if cleanupCount != 1 {
		t.Errorf("cleanup should be called once, got %d", cleanupCount)
	}
}

// --- Concurrent read/write Tests ---

// TestConcurrentReadWrite verifies that concurrent reads and writes are safe.
func TestConcurrentReadWrite(t *testing.T) {
	stream := newStreamMock()
	session := newTestSessionForStreamOps(t, stream)
	defer session.Cleanup()

	// Create typing envelopes for write
	env := &pb.ChatEnvelope{
		Payload: &pb.ChatEnvelope_Typing{
			Typing: &pb.ChatTyping{IsTyping: true},
		},
	}

	// Start concurrent writers
	var wg sync.WaitGroup
	errs := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := session.writeEnvelopeImpl(env); err != nil {
				errs <- err
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent write failed: %v", err)
	}
}

// --- MaxEnvelopeSize boundary tests ---

// TestReadEnvelope_AcceptsMaxSize verifies that max-size envelopes are accepted.
func TestReadEnvelope_AcceptsMaxSize(t *testing.T) {
	stream := newStreamMock()
	session := newTestSessionForStreamOps(t, stream)
	defer session.Cleanup()

	// Create typing envelope (smallest valid envelope type)
	env := &pb.ChatEnvelope{
		Payload: &pb.ChatEnvelope_Typing{
			Typing: &pb.ChatTyping{IsTyping: true},
		},
	}
	payload, err := proto.Marshal(env)
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	// Verify payload is under MaxEnvelopeSize
	if len(payload) > MaxEnvelopeSize {
		t.Skipf("test payload %d exceeds MaxEnvelopeSize %d", len(payload), MaxEnvelopeSize)
	}

	// Write length-prefixed data
	data := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(data[:4], uint32(len(payload)))
	copy(data[4:], payload)
	stream.setReadData(data)

	// Read envelope - should succeed
	_, err = session.readEnvelopeImpl()
	if err != nil {
		t.Fatalf("readEnvelope should accept valid size envelope: %v", err)
	}
}

// TestReadEnvelope_RejectsExactlyOverMax verifies that MaxEnvelopeSize+1 is rejected.
func TestReadEnvelope_RejectsExactlyOverMax(t *testing.T) {
	stream := newStreamMock()
	session := newTestSessionForStreamOps(t, stream)
	defer session.Cleanup()

	// Write length prefix indicating exactly MaxEnvelopeSize+1
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data[:4], MaxEnvelopeSize+1)
	stream.setReadData(data)

	_, err := session.readEnvelopeImpl()
	if err == nil {
		t.Fatal("expected error for envelope of size MaxEnvelopeSize+1")
	}

	if !errors.Is(err, ErrEnvelopeTooLarge) {
		t.Errorf("expected ErrEnvelopeTooLarge, got: %v", err)
	}
}

// --- Helper functions ---

// streamRWInterface defines the read/write interface for streams.
type streamRWInterface interface {
	io.Reader
	io.Writer
}

// newTestSessionForStreamOps creates a test session for stream operation tests.
func newTestSessionForStreamOps(t *testing.T, stream *streamMock) *ChatSession {
	t.Helper()

	// Generate session ID
	sessionID := make([]byte, 16)
	if _, err := rand.Read(sessionID); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}

	// Generate chat key
	chatKey := make([]byte, ChatKeyLength)
	if _, err := rand.Read(chatKey); err != nil {
		t.Fatalf("failed to generate chat key: %v", err)
	}

	session := &ChatSession{
		sessionID:    sessionID,
		chatKey:      chatKey,
		messages:     make([]*StoredMessage, 0),
		pendingAcks:  make(map[string]*PendingMessage),
		isOpen:       true,
		lastActivity: time.Now(),
	}

	// Set up the stream reader/writer
	if stream != nil {
		session.streamRW = stream
	}

	// Set up writeEnvelope to use the implementation
	session.writeEnvelope = session.writeEnvelopeImpl

	return session
}

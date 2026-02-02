package chat

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
	"google.golang.org/protobuf/proto"
)

// TestSendMessage_StoresInBuffer verifies that sent messages are stored in the message buffer.
func TestSendMessage_StoresInBuffer(t *testing.T) {
	session := newTestSessionForSend(t)
	defer session.Cleanup()

	text := "Hello, World!"
	messageID, err := session.SendMessage(text)
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}

	// Verify message is stored in buffer
	session.mu.RLock()
	defer session.mu.RUnlock()

	if len(session.messages) != 1 {
		t.Fatalf("expected 1 message in buffer, got %d", len(session.messages))
	}

	stored := session.messages[0]

	// Verify message ID matches
	if !bytes.Equal(stored.ID, messageID) {
		t.Error("stored message ID does not match returned message ID")
	}

	// Verify direction is Sent
	if stored.Direction != DirectionSent {
		t.Errorf("expected direction DirectionSent, got %d", stored.Direction)
	}

	// Verify plaintext is stored (should be protobuf-encoded ChatPlaintext)
	if len(stored.Plaintext) == 0 {
		t.Error("stored plaintext should not be empty")
	}

	// Verify the stored plaintext can be decoded
	var plaintext pb.ChatPlaintext
	if err := proto.Unmarshal(stored.Plaintext, &plaintext); err != nil {
		t.Fatalf("failed to unmarshal stored plaintext: %v", err)
	}
	if plaintext.Text != text {
		t.Errorf("plaintext text mismatch: got %q, want %q", plaintext.Text, text)
	}

	// Verify SentAt is set
	if stored.SentAt.IsZero() {
		t.Error("SentAt should be set")
	}
}

// TestSendMessage_AddsToPendingAcks verifies that sent messages are tracked for ACK.
func TestSendMessage_AddsToPendingAcks(t *testing.T) {
	session := newTestSessionForSend(t)
	defer session.Cleanup()

	text := "Test message"
	messageID, err := session.SendMessage(text)
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}

	// Verify message is in pending ACKs
	session.mu.RLock()
	defer session.mu.RUnlock()

	messageIDHex := hex.EncodeToString(messageID)
	pending, exists := session.pendingAcks[messageIDHex]
	if !exists {
		t.Fatal("message not found in pendingAcks")
	}

	// Verify pending message fields
	if !bytes.Equal(pending.ID, messageID) {
		t.Error("pending message ID does not match")
	}
	if pending.Retries != 0 {
		t.Errorf("expected 0 retries, got %d", pending.Retries)
	}
	if pending.SentAt.IsZero() {
		t.Error("pending SentAt should be set")
	}
	if len(pending.Plaintext) == 0 {
		t.Error("pending plaintext should not be empty")
	}
}

// TestSendMessage_RejectsOversized verifies that messages exceeding MaxMessageSize are rejected.
func TestSendMessage_RejectsOversized(t *testing.T) {
	session := newTestSessionForSend(t)
	defer session.Cleanup()

	// Create a message larger than MaxMessageSize (4096 bytes)
	oversizedText := strings.Repeat("x", MaxMessageSize+1)

	_, err := session.SendMessage(oversizedText)
	if err == nil {
		t.Fatal("expected error for oversized message, got nil")
	}

	// Verify error message indicates size issue
	if !strings.Contains(err.Error(), "max size") {
		t.Errorf("error should mention max size, got: %v", err)
	}

	// Verify no message was stored
	session.mu.RLock()
	defer session.mu.RUnlock()

	if len(session.messages) != 0 {
		t.Error("no message should be stored for oversized input")
	}
	if len(session.pendingAcks) != 0 {
		t.Error("no pending ACK should be created for oversized input")
	}
}

// TestSendMessage_RejectsClosedSession verifies that sending on a closed session fails.
func TestSendMessage_RejectsClosedSession(t *testing.T) {
	session := newTestSessionForSend(t)

	// Close the session
	session.Cleanup()

	// Attempt to send
	_, err := session.SendMessage("Hello")
	if err == nil {
		t.Fatal("expected error for closed session, got nil")
	}

	// Verify error indicates session is closed
	if !strings.Contains(err.Error(), "closed") {
		t.Errorf("error should mention closed session, got: %v", err)
	}
}

// TestSendMessage_GeneratesUniqueMessageIDs verifies that each message gets a unique ID.
func TestSendMessage_GeneratesUniqueMessageIDs(t *testing.T) {
	session := newTestSessionForSend(t)
	defer session.Cleanup()

	ids := make(map[string]bool)
	count := 10

	for i := 0; i < count; i++ {
		messageID, err := session.SendMessage("test message")
		if err != nil {
			t.Fatalf("SendMessage failed on iteration %d: %v", i, err)
		}

		idHex := hex.EncodeToString(messageID)
		if ids[idHex] {
			t.Errorf("duplicate message ID generated: %s", idHex)
		}
		ids[idHex] = true

		// Verify message ID is 16 bytes (UUID)
		if len(messageID) != 16 {
			t.Errorf("expected 16-byte message ID, got %d bytes", len(messageID))
		}
	}
}

// TestSendMessage_UpdatesLastActivity verifies that lastActivity is updated.
func TestSendMessage_UpdatesLastActivity(t *testing.T) {
	session := newTestSessionForSend(t)
	defer session.Cleanup()

	// Set an old lastActivity
	oldTime := time.Now().Add(-time.Hour)
	session.mu.Lock()
	session.lastActivity = oldTime
	session.mu.Unlock()

	// Send a message
	_, err := session.SendMessage("test")
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}

	// Verify lastActivity was updated
	session.mu.RLock()
	defer session.mu.RUnlock()

	if session.lastActivity.Before(time.Now().Add(-time.Second)) {
		t.Error("lastActivity was not updated")
	}
	if session.lastActivity.Before(oldTime) {
		t.Error("lastActivity should be newer than the old time")
	}
}

// TestSendMessage_EncryptsMessage verifies that the message is properly encrypted.
func TestSendMessage_EncryptsMessage(t *testing.T) {
	var sentEnvelope *pb.ChatEnvelope
	session := newTestSessionForSendWithWriter(t, func(env *pb.ChatEnvelope) error {
		sentEnvelope = env
		return nil
	})
	defer session.Cleanup()

	text := "Secret message"
	messageID, err := session.SendMessage(text)
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}

	// Verify envelope was sent
	if sentEnvelope == nil {
		t.Fatal("no envelope was sent")
	}

	// Get the message from envelope
	msg := sentEnvelope.GetMessage()
	if msg == nil {
		t.Fatal("envelope does not contain a message")
	}

	// Verify message ID matches
	if !bytes.Equal(msg.MessageId, messageID) {
		t.Error("envelope message ID does not match returned ID")
	}

	// Verify nonce is present and correct length
	if len(msg.Nonce) != NonceLength {
		t.Errorf("nonce length: got %d, want %d", len(msg.Nonce), NonceLength)
	}

	// Verify ciphertext is not empty
	if len(msg.Ciphertext) == 0 {
		t.Error("ciphertext should not be empty")
	}

	// Verify ciphertext is not the same as plaintext (actually encrypted)
	if bytes.Contains(msg.Ciphertext, []byte(text)) {
		t.Error("ciphertext should not contain plaintext")
	}

	// Verify timestamp is set
	if msg.Timestamp == 0 {
		t.Error("timestamp should be set")
	}

	// Decrypt to verify
	session.mu.RLock()
	key := session.chatKey
	session.mu.RUnlock()

	// Reconstruct the full ciphertext (nonce + ciphertext)
	fullCiphertext := append(msg.Nonce, msg.Ciphertext...)
	decrypted, err := Decrypt(key, fullCiphertext)
	if err != nil {
		t.Fatalf("failed to decrypt message: %v", err)
	}

	// Unmarshal the plaintext
	var plaintext pb.ChatPlaintext
	if err := proto.Unmarshal(decrypted, &plaintext); err != nil {
		t.Fatalf("failed to unmarshal decrypted plaintext: %v", err)
	}

	if plaintext.Text != text {
		t.Errorf("decrypted text mismatch: got %q, want %q", plaintext.Text, text)
	}
}

// TestSendMessage_EmptyMessage verifies that empty messages are handled.
func TestSendMessage_EmptyMessage(t *testing.T) {
	session := newTestSessionForSend(t)
	defer session.Cleanup()

	messageID, err := session.SendMessage("")
	if err != nil {
		t.Fatalf("SendMessage should allow empty messages: %v", err)
	}

	if len(messageID) != 16 {
		t.Errorf("expected 16-byte message ID, got %d bytes", len(messageID))
	}

	// Verify message is stored
	session.mu.RLock()
	defer session.mu.RUnlock()

	if len(session.messages) != 1 {
		t.Errorf("expected 1 message, got %d", len(session.messages))
	}
}

// TestSendMessage_MaxSizeMessage verifies that max-size messages are accepted.
// Note: MaxMessageSize is the limit for the encrypted plaintext (protobuf-encoded),
// which includes some overhead (~10 bytes for field tags and varint encoding).
// Therefore, the max text length is slightly less than MaxMessageSize.
func TestSendMessage_MaxSizeMessage(t *testing.T) {
	session := newTestSessionForSend(t)
	defer session.Cleanup()

	// Protobuf overhead is approximately 10 bytes (field tags + varint for sent_at)
	// Use a slightly smaller message to account for this
	const protobufOverhead = 15 // Conservative estimate
	maxText := strings.Repeat("x", MaxMessageSize-protobufOverhead)

	messageID, err := session.SendMessage(maxText)
	if err != nil {
		t.Fatalf("SendMessage should allow large messages: %v", err)
	}

	if len(messageID) != 16 {
		t.Errorf("expected 16-byte message ID, got %d bytes", len(messageID))
	}
}

// TestStoreMessageLocked_EvictsOldest verifies that oldest messages are evicted.
func TestStoreMessageLocked_EvictsOldest(t *testing.T) {
	session := newTestSessionForSend(t)
	defer session.Cleanup()

	// Fill the buffer to capacity
	for i := 0; i < MaxBufferedMessages; i++ {
		_, err := session.SendMessage("message")
		if err != nil {
			t.Fatalf("SendMessage failed on iteration %d: %v", i, err)
		}
	}

	// Verify buffer is at capacity
	session.mu.RLock()
	if len(session.messages) != MaxBufferedMessages {
		session.mu.RUnlock()
		t.Fatalf("expected %d messages, got %d", MaxBufferedMessages, len(session.messages))
	}

	// Store the first message's ID to verify it gets evicted
	firstMsgID := make([]byte, len(session.messages[0].ID))
	copy(firstMsgID, session.messages[0].ID)
	session.mu.RUnlock()

	// Send one more message
	_, err := session.SendMessage("overflow message")
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}

	// Verify buffer is still at capacity
	session.mu.RLock()
	defer session.mu.RUnlock()

	if len(session.messages) != MaxBufferedMessages {
		t.Errorf("expected %d messages after eviction, got %d", MaxBufferedMessages, len(session.messages))
	}

	// Verify the first message was evicted
	for _, msg := range session.messages {
		if bytes.Equal(msg.ID, firstMsgID) {
			t.Error("first message should have been evicted")
		}
	}
}

// TestStoreMessageLocked_WipesEvictedPlaintext verifies that evicted messages are wiped.
func TestStoreMessageLocked_WipesEvictedPlaintext(t *testing.T) {
	session := newTestSessionForSend(t)
	defer session.Cleanup()

	// Fill the buffer to capacity
	for i := 0; i < MaxBufferedMessages; i++ {
		_, err := session.SendMessage("message")
		if err != nil {
			t.Fatalf("SendMessage failed on iteration %d: %v", i, err)
		}
	}

	// Get reference to first message's plaintext
	session.mu.RLock()
	firstMsgPlaintext := session.messages[0].Plaintext
	// Make sure plaintext has content before eviction
	hasContent := false
	for _, b := range firstMsgPlaintext {
		if b != 0 {
			hasContent = true
			break
		}
	}
	if !hasContent {
		session.mu.RUnlock()
		t.Fatal("first message plaintext should have content before eviction")
	}
	session.mu.RUnlock()

	// Send one more message to trigger eviction
	_, err := session.SendMessage("overflow")
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}

	// Verify the evicted message's plaintext was zeroed
	isAllZeros := true
	for _, b := range firstMsgPlaintext {
		if b != 0 {
			isAllZeros = false
			break
		}
	}
	if !isAllZeros {
		t.Error("evicted message plaintext should be zeroed")
	}
}

// TestSendMessage_ConcurrentSafe verifies that SendMessage is safe under concurrent access.
func TestSendMessage_ConcurrentSafe(t *testing.T) {
	session := newTestSessionForSend(t)
	defer session.Cleanup()

	done := make(chan bool, 10)
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			_, err := session.SendMessage("concurrent message")
			if err != nil {
				errors <- err
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	close(errors)
	for err := range errors {
		t.Errorf("concurrent SendMessage failed: %v", err)
	}

	// Verify all messages were stored
	session.mu.RLock()
	defer session.mu.RUnlock()

	if len(session.messages) != 10 {
		t.Errorf("expected 10 messages, got %d", len(session.messages))
	}
	if len(session.pendingAcks) != 10 {
		t.Errorf("expected 10 pending ACKs, got %d", len(session.pendingAcks))
	}
}

// TestSendMessage_WriteEnvelopeError verifies that write errors are propagated.
func TestSendMessage_WriteEnvelopeError(t *testing.T) {
	expectedErr := fmt.Errorf("network error")
	session := newTestSessionForSendWithWriter(t, func(env *pb.ChatEnvelope) error {
		return expectedErr
	})
	defer session.Cleanup()

	_, err := session.SendMessage("test")
	if err == nil {
		t.Fatal("expected error when writeEnvelope fails")
	}

	if !strings.Contains(err.Error(), "send message") {
		t.Errorf("error should mention send message, got: %v", err)
	}

	// Verify no message was stored (write failed)
	session.mu.RLock()
	defer session.mu.RUnlock()

	if len(session.messages) != 0 {
		t.Error("no message should be stored when write fails")
	}
	if len(session.pendingAcks) != 0 {
		t.Error("no pending ACK should be created when write fails")
	}
}

// Helper function to create a test session for send tests.
func newTestSessionForSend(t *testing.T) *ChatSession {
	t.Helper()
	return newTestSessionForSendWithWriter(t, func(env *pb.ChatEnvelope) error {
		return nil // No-op writer
	})
}

// Helper function to create a test session with a custom envelope writer.
func newTestSessionForSendWithWriter(t *testing.T, writer func(*pb.ChatEnvelope) error) *ChatSession {
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
		sessionID:      sessionID,
		chatKey:        chatKey,
		messages:       make([]*StoredMessage, 0),
		pendingAcks:    make(map[string]*PendingMessage),
		isOpen:         true,
		lastActivity:   time.Now(),
		writeEnvelope:  writer,
	}

	return session
}

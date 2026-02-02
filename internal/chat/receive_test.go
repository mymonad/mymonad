package chat

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
	"google.golang.org/protobuf/proto"
)

// TestHandleMessage_DecryptsAndStores verifies that incoming messages are decrypted and stored.
func TestHandleMessage_DecryptsAndStores(t *testing.T) {
	var sentEnvelope *pb.ChatEnvelope
	session := newTestSessionForReceive(t, func(env *pb.ChatEnvelope) error {
		sentEnvelope = env
		return nil
	})
	defer session.Cleanup()

	// Prepare plaintext
	text := "Hello from peer!"
	sentAt := time.Now().UnixMilli()
	plaintext := &pb.ChatPlaintext{
		Text:   text,
		SentAt: sentAt,
	}
	plaintextBytes, err := proto.Marshal(plaintext)
	if err != nil {
		t.Fatalf("failed to marshal plaintext: %v", err)
	}

	// Encrypt the plaintext
	session.mu.RLock()
	chatKey := session.chatKey
	session.mu.RUnlock()

	ciphertext, err := Encrypt(chatKey, plaintextBytes)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Create message with nonce and ciphertext split
	messageID := make([]byte, 16)
	if _, err := rand.Read(messageID); err != nil {
		t.Fatalf("failed to generate message ID: %v", err)
	}

	msg := &pb.ChatMessage{
		MessageId:  messageID,
		Nonce:      ciphertext[:NonceLength],
		Ciphertext: ciphertext[NonceLength:],
		Timestamp:  time.Now().UnixMilli(),
	}

	// Handle the message
	session.handleMessage(msg)

	// Verify message is stored
	session.mu.RLock()
	defer session.mu.RUnlock()

	if len(session.messages) != 1 {
		t.Fatalf("expected 1 message in buffer, got %d", len(session.messages))
	}

	stored := session.messages[0]

	// Verify message ID matches
	if !bytes.Equal(stored.ID, messageID) {
		t.Error("stored message ID does not match")
	}

	// Verify direction is Received
	if stored.Direction != DirectionReceived {
		t.Errorf("expected direction DirectionReceived, got %d", stored.Direction)
	}

	// Verify plaintext is stored correctly
	if len(stored.Plaintext) == 0 {
		t.Error("stored plaintext should not be empty")
	}

	var storedContent pb.ChatPlaintext
	if err := proto.Unmarshal(stored.Plaintext, &storedContent); err != nil {
		t.Fatalf("failed to unmarshal stored plaintext: %v", err)
	}
	if storedContent.Text != text {
		t.Errorf("plaintext text mismatch: got %q, want %q", storedContent.Text, text)
	}

	// Verify ACK was sent
	if sentEnvelope == nil {
		t.Fatal("ACK envelope was not sent")
	}

	ack := sentEnvelope.GetAck()
	if ack == nil {
		t.Fatal("envelope does not contain an ACK")
	}

	// Verify ACK message ID matches
	if !bytes.Equal(ack.MessageId, messageID) {
		t.Error("ACK message ID does not match")
	}

	// Verify ACK hash is correct
	expectedHash := sha256Sum(plaintextBytes)
	if !bytes.Equal(ack.MessageHash, expectedHash) {
		t.Error("ACK message hash does not match expected hash")
	}
}

// TestHandleMessage_CallsOnMessageCallback verifies that the onMessage callback is called.
func TestHandleMessage_CallsOnMessageCallback(t *testing.T) {
	var receivedMsg *ReceivedMessage
	session := newTestSessionForReceive(t, func(env *pb.ChatEnvelope) error {
		return nil
	})
	session.onMessage = func(msg *ReceivedMessage) {
		receivedMsg = msg
	}
	defer session.Cleanup()

	// Prepare and send encrypted message
	text := "Callback test"
	sentAt := time.Now().UnixMilli()
	plaintext := &pb.ChatPlaintext{
		Text:   text,
		SentAt: sentAt,
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

	msg := &pb.ChatMessage{
		MessageId:  messageID,
		Nonce:      ciphertext[:NonceLength],
		Ciphertext: ciphertext[NonceLength:],
		Timestamp:  time.Now().UnixMilli(),
	}

	session.handleMessage(msg)

	// Verify callback was called
	if receivedMsg == nil {
		t.Fatal("onMessage callback was not called")
	}

	if !bytes.Equal(receivedMsg.ID, messageID) {
		t.Error("callback message ID does not match")
	}
}

// TestHandleMessage_DecryptionFailure verifies that decryption failures are handled gracefully.
func TestHandleMessage_DecryptionFailure(t *testing.T) {
	var sentEnvelope *pb.ChatEnvelope
	session := newTestSessionForReceive(t, func(env *pb.ChatEnvelope) error {
		sentEnvelope = env
		return nil
	})
	defer session.Cleanup()

	// Create message with invalid ciphertext
	messageID := make([]byte, 16)
	if _, err := rand.Read(messageID); err != nil {
		t.Fatalf("failed to generate message ID: %v", err)
	}

	invalidNonce := make([]byte, NonceLength)
	invalidCiphertext := make([]byte, 32) // Random garbage
	if _, err := rand.Read(invalidNonce); err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}
	if _, err := rand.Read(invalidCiphertext); err != nil {
		t.Fatalf("failed to generate ciphertext: %v", err)
	}

	msg := &pb.ChatMessage{
		MessageId:  messageID,
		Nonce:      invalidNonce,
		Ciphertext: invalidCiphertext,
		Timestamp:  time.Now().UnixMilli(),
	}

	// Handle message - should not panic
	session.handleMessage(msg)

	// Verify no message was stored
	session.mu.RLock()
	defer session.mu.RUnlock()

	if len(session.messages) != 0 {
		t.Error("no message should be stored on decryption failure")
	}

	// Verify no ACK was sent
	if sentEnvelope != nil {
		t.Error("no ACK should be sent on decryption failure")
	}
}

// TestHandleMessage_InvalidPlaintext verifies that invalid plaintext is handled gracefully.
func TestHandleMessage_InvalidPlaintext(t *testing.T) {
	var sentEnvelope *pb.ChatEnvelope
	session := newTestSessionForReceive(t, func(env *pb.ChatEnvelope) error {
		sentEnvelope = env
		return nil
	})
	defer session.Cleanup()

	// Encrypt invalid protobuf data
	session.mu.RLock()
	chatKey := session.chatKey
	session.mu.RUnlock()

	invalidPlaintext := []byte{0xff, 0xff, 0xff, 0xff} // Invalid protobuf
	ciphertext, err := Encrypt(chatKey, invalidPlaintext)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	messageID := make([]byte, 16)
	if _, err := rand.Read(messageID); err != nil {
		t.Fatalf("failed to generate message ID: %v", err)
	}

	msg := &pb.ChatMessage{
		MessageId:  messageID,
		Nonce:      ciphertext[:NonceLength],
		Ciphertext: ciphertext[NonceLength:],
		Timestamp:  time.Now().UnixMilli(),
	}

	// Handle message - should not panic
	session.handleMessage(msg)

	// Verify no message was stored
	session.mu.RLock()
	defer session.mu.RUnlock()

	if len(session.messages) != 0 {
		t.Error("no message should be stored on invalid plaintext")
	}

	// Verify no ACK was sent
	if sentEnvelope != nil {
		t.Error("no ACK should be sent on invalid plaintext")
	}
}

// TestHandleMessage_UpdatesLastActivity verifies that lastActivity is updated.
func TestHandleMessage_UpdatesLastActivity(t *testing.T) {
	session := newTestSessionForReceive(t, func(env *pb.ChatEnvelope) error {
		return nil
	})
	defer session.Cleanup()

	// Set old lastActivity
	oldTime := time.Now().Add(-time.Hour)
	session.mu.Lock()
	session.lastActivity = oldTime
	session.mu.Unlock()

	// Send a valid encrypted message
	text := "Update activity test"
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

	msg := &pb.ChatMessage{
		MessageId:  messageID,
		Nonce:      ciphertext[:NonceLength],
		Ciphertext: ciphertext[NonceLength:],
		Timestamp:  time.Now().UnixMilli(),
	}

	session.handleMessage(msg)

	// Verify lastActivity was updated
	session.mu.RLock()
	defer session.mu.RUnlock()

	if session.lastActivity.Before(time.Now().Add(-time.Second)) {
		t.Error("lastActivity was not updated")
	}
}

// TestHandleAck_MarksDelivered verifies that ACKs mark messages as delivered.
func TestHandleAck_MarksDelivered(t *testing.T) {
	var deliveredID []byte
	session := newTestSessionForReceive(t, func(env *pb.ChatEnvelope) error {
		return nil
	})
	session.onDelivered = func(messageID []byte) {
		deliveredID = messageID
	}
	defer session.Cleanup()

	// First send a message (simulate)
	text := "Test message"
	messageID, err := session.SendMessage(text)
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}

	// Get the plaintext from pending
	session.mu.RLock()
	idHex := hex.EncodeToString(messageID)
	pending, ok := session.pendingAcks[idHex]
	if !ok {
		session.mu.RUnlock()
		t.Fatal("message not found in pendingAcks")
	}
	plaintextHash := sha256Sum(pending.Plaintext)
	session.mu.RUnlock()

	// Create ACK with correct hash
	ack := &pb.ChatAck{
		MessageId:   messageID,
		MessageHash: plaintextHash,
	}

	// Handle the ACK
	session.handleAck(ack)

	// Verify removed from pendingAcks
	session.mu.RLock()
	defer session.mu.RUnlock()

	if _, exists := session.pendingAcks[idHex]; exists {
		t.Error("message should be removed from pendingAcks after ACK")
	}

	// Verify DeliveredAt is set
	var found bool
	for _, msg := range session.messages {
		if bytes.Equal(msg.ID, messageID) {
			found = true
			if msg.DeliveredAt == nil {
				t.Error("DeliveredAt should be set after ACK")
			}
			break
		}
	}
	if !found {
		t.Error("message not found in messages buffer")
	}

	// Verify callback was called
	if !bytes.Equal(deliveredID, messageID) {
		t.Error("onDelivered callback was not called with correct message ID")
	}
}

// TestHandleAck_RejectsHashMismatch verifies that ACKs with wrong hash are rejected.
func TestHandleAck_RejectsHashMismatch(t *testing.T) {
	var deliveredCalled bool
	session := newTestSessionForReceive(t, func(env *pb.ChatEnvelope) error {
		return nil
	})
	session.onDelivered = func(messageID []byte) {
		deliveredCalled = true
	}
	defer session.Cleanup()

	// Send a message
	text := "Test message"
	messageID, err := session.SendMessage(text)
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}

	idHex := hex.EncodeToString(messageID)

	// Create ACK with WRONG hash
	wrongHash := sha256Sum([]byte("wrong plaintext"))
	ack := &pb.ChatAck{
		MessageId:   messageID,
		MessageHash: wrongHash,
	}

	// Handle the ACK
	session.handleAck(ack)

	// Verify message is STILL in pendingAcks
	session.mu.RLock()
	defer session.mu.RUnlock()

	if _, exists := session.pendingAcks[idHex]; !exists {
		t.Error("message should still be in pendingAcks after hash mismatch")
	}

	// Verify DeliveredAt is NOT set
	for _, msg := range session.messages {
		if bytes.Equal(msg.ID, messageID) {
			if msg.DeliveredAt != nil {
				t.Error("DeliveredAt should NOT be set after hash mismatch")
			}
			break
		}
	}

	// Verify callback was NOT called
	if deliveredCalled {
		t.Error("onDelivered callback should not be called on hash mismatch")
	}
}

// TestHandleAck_UnknownMessageID verifies that ACKs for unknown messages are ignored.
func TestHandleAck_UnknownMessageID(t *testing.T) {
	var deliveredCalled bool
	session := newTestSessionForReceive(t, func(env *pb.ChatEnvelope) error {
		return nil
	})
	session.onDelivered = func(messageID []byte) {
		deliveredCalled = true
	}
	defer session.Cleanup()

	// Create ACK for unknown message
	unknownID := make([]byte, 16)
	if _, err := rand.Read(unknownID); err != nil {
		t.Fatalf("failed to generate message ID: %v", err)
	}
	someHash := sha256Sum([]byte("some data"))

	ack := &pb.ChatAck{
		MessageId:   unknownID,
		MessageHash: someHash,
	}

	// Handle the ACK - should not panic
	session.handleAck(ack)

	// Verify callback was NOT called
	if deliveredCalled {
		t.Error("onDelivered callback should not be called for unknown message")
	}
}

// TestHandleAck_UpdatesLastActivity verifies that lastActivity is updated on ACK.
func TestHandleAck_UpdatesLastActivity(t *testing.T) {
	session := newTestSessionForReceive(t, func(env *pb.ChatEnvelope) error {
		return nil
	})
	defer session.Cleanup()

	// Send a message
	messageID, err := session.SendMessage("test")
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}

	// Get correct hash
	session.mu.RLock()
	idHex := hex.EncodeToString(messageID)
	pending := session.pendingAcks[idHex]
	plaintextHash := sha256Sum(pending.Plaintext)
	session.mu.RUnlock()

	// Set old lastActivity
	oldTime := time.Now().Add(-time.Hour)
	session.mu.Lock()
	session.lastActivity = oldTime
	session.mu.Unlock()

	// Handle ACK
	ack := &pb.ChatAck{
		MessageId:   messageID,
		MessageHash: plaintextHash,
	}
	session.handleAck(ack)

	// Verify lastActivity was updated
	session.mu.RLock()
	defer session.mu.RUnlock()

	if session.lastActivity.Before(time.Now().Add(-time.Second)) {
		t.Error("lastActivity was not updated")
	}
}

// TestHandleAck_DuplicateACK verifies that duplicate ACKs are ignored.
func TestHandleAck_DuplicateACK(t *testing.T) {
	callCount := 0
	session := newTestSessionForReceive(t, func(env *pb.ChatEnvelope) error {
		return nil
	})
	session.onDelivered = func(messageID []byte) {
		callCount++
	}
	defer session.Cleanup()

	// Send a message
	messageID, err := session.SendMessage("test")
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}

	// Get correct hash
	session.mu.RLock()
	idHex := hex.EncodeToString(messageID)
	pending := session.pendingAcks[idHex]
	plaintextHash := sha256Sum(pending.Plaintext)
	session.mu.RUnlock()

	ack := &pb.ChatAck{
		MessageId:   messageID,
		MessageHash: plaintextHash,
	}

	// Handle ACK twice
	session.handleAck(ack)
	session.handleAck(ack)

	// Verify callback was called only once
	if callCount != 1 {
		t.Errorf("onDelivered callback should be called once, got %d", callCount)
	}
}

// TestSha256Sum verifies the sha256Sum helper function.
func TestSha256Sum(t *testing.T) {
	data := []byte("test data")
	hash := sha256Sum(data)

	// Verify hash length
	if len(hash) != 32 {
		t.Errorf("expected 32-byte hash, got %d bytes", len(hash))
	}

	// Verify hash is deterministic
	hash2 := sha256Sum(data)
	if !bytes.Equal(hash, hash2) {
		t.Error("sha256Sum should be deterministic")
	}

	// Verify against standard library
	expected := sha256.Sum256(data)
	if !bytes.Equal(hash, expected[:]) {
		t.Error("sha256Sum does not match crypto/sha256")
	}

	// Verify different data produces different hash
	hash3 := sha256Sum([]byte("different data"))
	if bytes.Equal(hash, hash3) {
		t.Error("different data should produce different hash")
	}
}

// TestHandleMessage_ACKWriteError verifies that ACK write errors don't prevent message storage.
func TestHandleMessage_ACKWriteError(t *testing.T) {
	session := newTestSessionForReceive(t, func(env *pb.ChatEnvelope) error {
		return errACKWriteFailed // Simulate write failure
	})
	defer session.Cleanup()

	// Prepare and send encrypted message
	text := "Test message"
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

	msg := &pb.ChatMessage{
		MessageId:  messageID,
		Nonce:      ciphertext[:NonceLength],
		Ciphertext: ciphertext[NonceLength:],
		Timestamp:  time.Now().UnixMilli(),
	}

	// Handle message - ACK should fail but message should still be stored
	session.handleMessage(msg)

	// Verify message is still stored despite ACK failure
	session.mu.RLock()
	defer session.mu.RUnlock()

	if len(session.messages) != 1 {
		t.Error("message should be stored even if ACK write fails")
	}
}

// Error for testing ACK write failures.
var errACKWriteFailed = &ackWriteError{}

type ackWriteError struct{}

func (e *ackWriteError) Error() string {
	return "ACK write failed"
}

// Helper function to create a test session for receive tests.
func newTestSessionForReceive(t *testing.T, writer func(*pb.ChatEnvelope) error) *ChatSession {
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
		sessionID:     sessionID,
		chatKey:       chatKey,
		messages:      make([]*StoredMessage, 0),
		pendingAcks:   make(map[string]*PendingMessage),
		isOpen:        true,
		lastActivity:  time.Now(),
		writeEnvelope: writer,
	}

	return session
}

package chat

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

// TestZeroFill_ZerosAllBytes verifies that zeroFill sets all bytes to zero.
func TestZeroFill_ZerosAllBytes(t *testing.T) {
	// Create a buffer with non-zero data
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}

	// Verify data is not all zeros before zeroing
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("test data should not be all zeros before zeroFill")
	}

	// Zero the data
	zeroFill(data)

	// Verify all bytes are zero
	for i, b := range data {
		if b != 0 {
			t.Errorf("byte at index %d is not zero: got %d", i, b)
		}
	}
}

// TestZeroFill_EmptySlice verifies that zeroFill handles empty slices.
func TestZeroFill_EmptySlice(t *testing.T) {
	data := []byte{}
	// Should not panic
	zeroFill(data)
	if len(data) != 0 {
		t.Error("empty slice should remain empty")
	}
}

// TestZeroFill_NilSlice verifies that zeroFill handles nil slices.
func TestZeroFill_NilSlice(t *testing.T) {
	var data []byte
	// Should not panic
	zeroFill(data)
	if data != nil {
		t.Error("nil slice should remain nil")
	}
}

// TestZeroFill_VariousSizes verifies zeroFill works for different sizes.
func TestZeroFill_VariousSizes(t *testing.T) {
	sizes := []int{1, 7, 16, 32, 64, 128, 255, 1024}

	for _, size := range sizes {
		data := make([]byte, size)
		if _, err := rand.Read(data); err != nil {
			t.Fatalf("failed to generate random data for size %d: %v", size, err)
		}

		zeroFill(data)

		for i, b := range data {
			if b != 0 {
				t.Errorf("size %d: byte at index %d is not zero", size, i)
			}
		}
	}
}

// TestCleanup_ZerosAllSensitiveData verifies that Cleanup wipes all sensitive data.
func TestCleanup_ZerosAllSensitiveData(t *testing.T) {
	// Create test data
	sessionID := make([]byte, 16)
	chatKey := make([]byte, 32)
	msgPlaintext := make([]byte, 64)
	msgID := make([]byte, 16)
	pendingPlaintext := make([]byte, 64)
	pendingID := make([]byte, 16)

	// Fill with random data
	rand.Read(sessionID)
	rand.Read(chatKey)
	rand.Read(msgPlaintext)
	rand.Read(msgID)
	rand.Read(pendingPlaintext)
	rand.Read(pendingID)

	// Keep copies for verification
	sessionIDCopy := make([]byte, len(sessionID))
	chatKeyCopy := make([]byte, len(chatKey))
	msgPlaintextCopy := make([]byte, len(msgPlaintext))
	msgIDCopy := make([]byte, len(msgID))
	pendingPlaintextCopy := make([]byte, len(pendingPlaintext))
	pendingIDCopy := make([]byte, len(pendingID))

	copy(sessionIDCopy, sessionID)
	copy(chatKeyCopy, chatKey)
	copy(msgPlaintextCopy, msgPlaintext)
	copy(msgIDCopy, msgID)
	copy(pendingPlaintextCopy, pendingPlaintext)
	copy(pendingIDCopy, pendingID)

	// Create session with messages
	session := &ChatSession{
		sessionID: sessionID,
		chatKey:   chatKey,
		messages: []*StoredMessage{
			{
				ID:        msgID,
				Plaintext: msgPlaintext,
				SentAt:    time.Now(),
				Direction: DirectionSent,
			},
		},
		pendingAcks: map[string]*PendingMessage{
			"test-pending": {
				ID:        pendingID,
				Plaintext: pendingPlaintext,
				SentAt:    time.Now(),
				Retries:   0,
			},
		},
		isOpen: true,
	}

	// Store references to the underlying byte slices
	sessionIDRef := session.sessionID
	chatKeyRef := session.chatKey
	msgPlaintextRef := session.messages[0].Plaintext
	msgIDRef := session.messages[0].ID
	pendingPlaintextRef := session.pendingAcks["test-pending"].Plaintext
	pendingIDRef := session.pendingAcks["test-pending"].ID

	// Call Cleanup
	session.Cleanup()

	// Verify session is closed
	if session.isOpen {
		t.Error("session should be closed after Cleanup")
	}

	// Verify all sensitive data is zeroed (check the underlying slices)
	if !isAllZeros(sessionIDRef) {
		t.Error("sessionID was not zeroed")
	}
	if !isAllZeros(chatKeyRef) {
		t.Error("chatKey was not zeroed")
	}
	if !isAllZeros(msgPlaintextRef) {
		t.Error("message plaintext was not zeroed")
	}
	if !isAllZeros(msgIDRef) {
		t.Error("message ID was not zeroed")
	}
	if !isAllZeros(pendingPlaintextRef) {
		t.Error("pending message plaintext was not zeroed")
	}
	if !isAllZeros(pendingIDRef) {
		t.Error("pending message ID was not zeroed")
	}

	// Verify fields are nil after cleanup
	if session.chatKey != nil {
		t.Error("chatKey should be nil after Cleanup")
	}
	if session.messages != nil {
		t.Error("messages should be nil after Cleanup")
	}
	if session.pendingAcks != nil {
		t.Error("pendingAcks should be nil after Cleanup")
	}
}

// TestCleanup_Idempotent verifies that Cleanup can be called multiple times safely.
func TestCleanup_Idempotent(t *testing.T) {
	// Create a session
	sessionID := make([]byte, 16)
	chatKey := make([]byte, 32)
	rand.Read(sessionID)
	rand.Read(chatKey)

	cleanupCalled := 0
	session := &ChatSession{
		sessionID: sessionID,
		chatKey:   chatKey,
		messages:  []*StoredMessage{},
		pendingAcks: map[string]*PendingMessage{},
		isOpen:    true,
		onCleanup: func() {
			cleanupCalled++
		},
	}

	// First cleanup
	session.Cleanup()

	// Verify cleanup was called once
	if cleanupCalled != 1 {
		t.Errorf("onCleanup should be called once, got %d", cleanupCalled)
	}

	// Second cleanup should not panic and should not call onCleanup again
	session.Cleanup()

	// Verify cleanup was not called again
	if cleanupCalled != 1 {
		t.Errorf("onCleanup should still be 1 after second Cleanup, got %d", cleanupCalled)
	}

	// Third cleanup for good measure
	session.Cleanup()

	if cleanupCalled != 1 {
		t.Errorf("onCleanup should still be 1 after third Cleanup, got %d", cleanupCalled)
	}
}

// TestCleanup_CallsOnCleanupCallback verifies that the onCleanup callback is called.
func TestCleanup_CallsOnCleanupCallback(t *testing.T) {
	callbackCalled := false

	session := &ChatSession{
		sessionID:   make([]byte, 16),
		chatKey:     make([]byte, 32),
		isOpen:      true,
		pendingAcks: map[string]*PendingMessage{},
		onCleanup: func() {
			callbackCalled = true
		},
	}

	session.Cleanup()

	if !callbackCalled {
		t.Error("onCleanup callback should have been called")
	}
}

// TestCleanup_NoCallbackDoesNotPanic verifies cleanup works without callback.
func TestCleanup_NoCallbackDoesNotPanic(t *testing.T) {
	session := &ChatSession{
		sessionID:   make([]byte, 16),
		chatKey:     make([]byte, 32),
		isOpen:      true,
		pendingAcks: map[string]*PendingMessage{},
		onCleanup:   nil, // No callback
	}

	// Should not panic
	session.Cleanup()

	if session.isOpen {
		t.Error("session should be closed after Cleanup")
	}
}

// TestCleanup_AlreadyClosedSession verifies cleanup on already closed session.
func TestCleanup_AlreadyClosedSession(t *testing.T) {
	session := &ChatSession{
		isOpen: false, // Already closed
	}

	// Should not panic
	session.Cleanup()

	// Should still be closed
	if session.isOpen {
		t.Error("session should remain closed")
	}
}

// TestCleanup_WithMultipleMessages verifies cleanup with multiple messages.
func TestCleanup_WithMultipleMessages(t *testing.T) {
	// Create multiple messages
	messages := make([]*StoredMessage, 5)
	msgRefs := make([][]byte, 5)
	idRefs := make([][]byte, 5)

	for i := 0; i < 5; i++ {
		plaintext := make([]byte, 32)
		id := make([]byte, 16)
		rand.Read(plaintext)
		rand.Read(id)

		messages[i] = &StoredMessage{
			ID:        id,
			Plaintext: plaintext,
			SentAt:    time.Now(),
			Direction: DirectionReceived,
		}
		msgRefs[i] = plaintext
		idRefs[i] = id
	}

	// Create pending messages
	pendingAcks := make(map[string]*PendingMessage)
	pendingRefs := make(map[string][]byte)
	pendingIDRefs := make(map[string][]byte)

	for i := 0; i < 3; i++ {
		key := string(make([]byte, 8))
		plaintext := make([]byte, 64)
		id := make([]byte, 16)
		rand.Read(plaintext)
		rand.Read(id)

		pendingAcks[key] = &PendingMessage{
			ID:        id,
			Plaintext: plaintext,
			SentAt:    time.Now(),
			Retries:   i,
		}
		pendingRefs[key] = plaintext
		pendingIDRefs[key] = id
	}

	session := &ChatSession{
		sessionID:   make([]byte, 16),
		chatKey:     make([]byte, 32),
		messages:    messages,
		pendingAcks: pendingAcks,
		isOpen:      true,
	}

	session.Cleanup()

	// Verify all message plaintexts are zeroed
	for i, ref := range msgRefs {
		if !isAllZeros(ref) {
			t.Errorf("message %d plaintext was not zeroed", i)
		}
	}

	// Verify all message IDs are zeroed
	for i, ref := range idRefs {
		if !isAllZeros(ref) {
			t.Errorf("message %d ID was not zeroed", i)
		}
	}

	// Verify all pending message plaintexts are zeroed
	for key, ref := range pendingRefs {
		if !isAllZeros(ref) {
			t.Errorf("pending message %q plaintext was not zeroed", key)
		}
	}

	// Verify all pending message IDs are zeroed
	for key, ref := range pendingIDRefs {
		if !isAllZeros(ref) {
			t.Errorf("pending message %q ID was not zeroed", key)
		}
	}
}

// TestCleanup_NilFields verifies cleanup handles nil fields gracefully.
func TestCleanup_NilFields(t *testing.T) {
	session := &ChatSession{
		sessionID:   nil,
		chatKey:     nil,
		messages:    nil,
		pendingAcks: nil,
		isOpen:      true,
	}

	// Should not panic
	session.Cleanup()

	if session.isOpen {
		t.Error("session should be closed after Cleanup")
	}
}

// TestCleanup_ConcurrentSafe verifies cleanup is safe under concurrent access.
func TestCleanup_ConcurrentSafe(t *testing.T) {
	session := &ChatSession{
		sessionID:   make([]byte, 16),
		chatKey:     make([]byte, 32),
		messages:    []*StoredMessage{},
		pendingAcks: map[string]*PendingMessage{},
		isOpen:      true,
	}

	// Run multiple cleanup calls concurrently
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			session.Cleanup()
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Session should be closed
	if session.isOpen {
		t.Error("session should be closed after concurrent Cleanup calls")
	}
}

// TestMessageDirection_Constants verifies the MessageDirection constants.
func TestMessageDirection_Constants(t *testing.T) {
	if DirectionSent != 0 {
		t.Errorf("DirectionSent should be 0, got %d", DirectionSent)
	}
	if DirectionReceived != 1 {
		t.Errorf("DirectionReceived should be 1, got %d", DirectionReceived)
	}
}

// TestSessionConstants verifies the session constants are set correctly.
func TestSessionConstants(t *testing.T) {
	if MaxBufferedMessages != 100 {
		t.Errorf("MaxBufferedMessages should be 100, got %d", MaxBufferedMessages)
	}
	if MaxRetries != 5 {
		t.Errorf("MaxRetries should be 5, got %d", MaxRetries)
	}
}

// TestStoredMessage_Fields verifies StoredMessage struct fields.
func TestStoredMessage_Fields(t *testing.T) {
	now := time.Now()
	delivered := now.Add(time.Second)

	msg := &StoredMessage{
		ID:          []byte("test-id"),
		Plaintext:   []byte("test message"),
		SentAt:      now,
		DeliveredAt: &delivered,
		Direction:   DirectionSent,
	}

	if !bytes.Equal(msg.ID, []byte("test-id")) {
		t.Error("ID mismatch")
	}
	if !bytes.Equal(msg.Plaintext, []byte("test message")) {
		t.Error("Plaintext mismatch")
	}
	if !msg.SentAt.Equal(now) {
		t.Error("SentAt mismatch")
	}
	if msg.DeliveredAt == nil || !msg.DeliveredAt.Equal(delivered) {
		t.Error("DeliveredAt mismatch")
	}
	if msg.Direction != DirectionSent {
		t.Error("Direction mismatch")
	}
}

// TestPendingMessage_Fields verifies PendingMessage struct fields.
func TestPendingMessage_Fields(t *testing.T) {
	now := time.Now()

	pending := &PendingMessage{
		ID:        []byte("pending-id"),
		Plaintext: []byte("pending message"),
		SentAt:    now,
		Retries:   3,
	}

	if !bytes.Equal(pending.ID, []byte("pending-id")) {
		t.Error("ID mismatch")
	}
	if !bytes.Equal(pending.Plaintext, []byte("pending message")) {
		t.Error("Plaintext mismatch")
	}
	if !pending.SentAt.Equal(now) {
		t.Error("SentAt mismatch")
	}
	if pending.Retries != 3 {
		t.Error("Retries mismatch")
	}
}

// isAllZeros is a helper to check if a byte slice is all zeros.
func isAllZeros(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

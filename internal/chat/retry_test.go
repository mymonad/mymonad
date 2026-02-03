package chat

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
)

// TestRetryPending_IncrementsCounter verifies that retryPending increments the retry counter.
func TestRetryPending_IncrementsCounter(t *testing.T) {
	// Create session with pending message
	session := newTestSessionForRetry(t)
	defer session.Cleanup()

	// Add a pending message with 0 retries
	msgID := make([]byte, 16)
	rand.Read(msgID)
	msgIDHex := hex.EncodeToString(msgID)

	session.mu.Lock()
	session.pendingAcks[msgIDHex] = &PendingMessage{
		ID:        msgID,
		Plaintext: []byte("test message"),
		SentAt:    time.Now(),
		Retries:   0,
	}
	session.mu.Unlock()

	// Call retryPending
	session.retryPending()

	// Verify Retries counter increased
	session.mu.RLock()
	pending, exists := session.pendingAcks[msgIDHex]
	session.mu.RUnlock()

	if !exists {
		t.Fatal("pending message should still exist")
	}
	if pending.Retries != 1 {
		t.Errorf("expected retries = 1, got %d", pending.Retries)
	}
}

// TestRetryPending_IncrementsMultipleMessages verifies that retryPending increments all pending messages.
func TestRetryPending_IncrementsMultipleMessages(t *testing.T) {
	session := newTestSessionForRetry(t)
	defer session.Cleanup()

	// Add multiple pending messages with different retry counts
	messages := []struct {
		id           []byte
		initialRetry int
	}{
		{make([]byte, 16), 0},
		{make([]byte, 16), 1},
		{make([]byte, 16), 2},
	}

	session.mu.Lock()
	for _, msg := range messages {
		rand.Read(msg.id)
		session.pendingAcks[hex.EncodeToString(msg.id)] = &PendingMessage{
			ID:        msg.id,
			Plaintext: []byte("test"),
			SentAt:    time.Now(),
			Retries:   msg.initialRetry,
		}
	}
	session.mu.Unlock()

	// Call retryPending
	session.retryPending()

	// Verify all counters incremented
	session.mu.RLock()
	defer session.mu.RUnlock()

	for i, msg := range messages {
		pending := session.pendingAcks[hex.EncodeToString(msg.id)]
		expected := msg.initialRetry + 1
		if pending.Retries != expected {
			t.Errorf("message %d: expected retries = %d, got %d", i, expected, pending.Retries)
		}
	}
}

// TestRetryPending_TriggersCleanupOnMaxRetries verifies that exceeding MaxRetries triggers cleanup.
func TestRetryPending_TriggersCleanupOnMaxRetries(t *testing.T) {
	session := newTestSessionForRetry(t)

	// Add a pending message at MaxRetries
	msgID := make([]byte, 16)
	rand.Read(msgID)
	msgIDHex := hex.EncodeToString(msgID)

	session.mu.Lock()
	session.pendingAcks[msgIDHex] = &PendingMessage{
		ID:        msgID,
		Plaintext: []byte("test message"),
		SentAt:    time.Now(),
		Retries:   MaxRetries, // At max, one more increment will exceed
	}
	session.mu.Unlock()

	// Call retryPending
	session.retryPending()

	// Verify session is cleaned up (isOpen = false)
	session.mu.RLock()
	isOpen := session.isOpen
	session.mu.RUnlock()

	if isOpen {
		t.Error("session should be closed after exceeding MaxRetries")
	}
}

// TestRetryPending_CallsOnCleanupWhenMaxRetriesExceeded verifies callback is called.
func TestRetryPending_CallsOnCleanupWhenMaxRetriesExceeded(t *testing.T) {
	cleanupCalled := false
	session := newTestSessionForRetryWithCleanupCallback(t, func() {
		cleanupCalled = true
	})

	// Add a pending message at MaxRetries
	msgID := make([]byte, 16)
	rand.Read(msgID)
	msgIDHex := hex.EncodeToString(msgID)

	session.mu.Lock()
	session.pendingAcks[msgIDHex] = &PendingMessage{
		ID:        msgID,
		Plaintext: []byte("test message"),
		SentAt:    time.Now(),
		Retries:   MaxRetries,
	}
	session.mu.Unlock()

	// Call retryPending
	session.retryPending()

	if !cleanupCalled {
		t.Error("onCleanup callback should have been called when MaxRetries exceeded")
	}
}

// TestRetryPending_ResendsMessage verifies that pending messages are resent.
func TestRetryPending_ResendsMessage(t *testing.T) {
	var sentEnvelopes []*pb.ChatEnvelope
	var mu sync.Mutex

	session := newTestSessionForRetryWithWriter(t, func(env *pb.ChatEnvelope) error {
		mu.Lock()
		sentEnvelopes = append(sentEnvelopes, env)
		mu.Unlock()
		return nil
	})
	defer session.Cleanup()

	// Add a pending message
	msgID := make([]byte, 16)
	rand.Read(msgID)
	msgIDHex := hex.EncodeToString(msgID)
	plaintext := []byte("test message content")

	session.mu.Lock()
	session.pendingAcks[msgIDHex] = &PendingMessage{
		ID:        msgID,
		Plaintext: plaintext,
		SentAt:    time.Now(),
		Retries:   0,
	}
	session.mu.Unlock()

	// Call retryPending
	session.retryPending()

	// Verify message was resent
	mu.Lock()
	defer mu.Unlock()

	if len(sentEnvelopes) != 1 {
		t.Fatalf("expected 1 envelope sent, got %d", len(sentEnvelopes))
	}

	// Verify the envelope contains a message
	msg := sentEnvelopes[0].GetMessage()
	if msg == nil {
		t.Fatal("expected message in envelope")
	}
}

// TestRetryPending_NoPendingMessages verifies retryPending handles empty pending map.
func TestRetryPending_NoPendingMessages(t *testing.T) {
	session := newTestSessionForRetry(t)
	defer session.Cleanup()

	// Ensure no pending messages
	session.mu.Lock()
	session.pendingAcks = make(map[string]*PendingMessage)
	session.mu.Unlock()

	// Should not panic
	session.retryPending()

	// Session should still be open
	session.mu.RLock()
	isOpen := session.isOpen
	session.mu.RUnlock()

	if !isOpen {
		t.Error("session should remain open with no pending messages")
	}
}

// TestRetryPending_ClosedSession verifies retryPending on closed session does nothing.
func TestRetryPending_ClosedSession(t *testing.T) {
	session := newTestSessionForRetry(t)

	// Add pending message
	msgID := make([]byte, 16)
	rand.Read(msgID)
	msgIDHex := hex.EncodeToString(msgID)

	session.mu.Lock()
	session.pendingAcks[msgIDHex] = &PendingMessage{
		ID:        msgID,
		Plaintext: []byte("test"),
		SentAt:    time.Now(),
		Retries:   0,
	}
	session.mu.Unlock()

	// Close the session
	session.Cleanup()

	// Call retryPending - should not panic and should do nothing
	session.retryPending()

	// Session should still be closed
	session.mu.RLock()
	isOpen := session.isOpen
	session.mu.RUnlock()

	if isOpen {
		t.Error("session should remain closed")
	}
}

// TestRetryPending_ContinuesOnSendError verifies retry continues after send error.
func TestRetryPending_ContinuesOnSendError(t *testing.T) {
	sendCount := 0
	session := newTestSessionForRetryWithWriter(t, func(env *pb.ChatEnvelope) error {
		sendCount++
		return nil // First send succeeds
	})
	defer session.Cleanup()

	// Add multiple pending messages
	for i := 0; i < 3; i++ {
		msgID := make([]byte, 16)
		rand.Read(msgID)
		session.mu.Lock()
		session.pendingAcks[hex.EncodeToString(msgID)] = &PendingMessage{
			ID:        msgID,
			Plaintext: []byte("test"),
			SentAt:    time.Now(),
			Retries:   0,
		}
		session.mu.Unlock()
	}

	// Call retryPending
	session.retryPending()

	// Verify all 3 messages were attempted
	if sendCount != 3 {
		t.Errorf("expected 3 send attempts, got %d", sendCount)
	}
}

// TestRetryPending_StopsAtFirstMaxRetries verifies that cleanup stops iteration.
func TestRetryPending_StopsAtFirstMaxRetries(t *testing.T) {
	session := newTestSessionForRetry(t)

	// Add multiple pending messages, one at MaxRetries
	msg1 := make([]byte, 16)
	msg2 := make([]byte, 16)
	rand.Read(msg1)
	rand.Read(msg2)

	session.mu.Lock()
	session.pendingAcks[hex.EncodeToString(msg1)] = &PendingMessage{
		ID:        msg1,
		Plaintext: []byte("test1"),
		SentAt:    time.Now(),
		Retries:   MaxRetries, // Will exceed
	}
	session.pendingAcks[hex.EncodeToString(msg2)] = &PendingMessage{
		ID:        msg2,
		Plaintext: []byte("test2"),
		SentAt:    time.Now(),
		Retries:   0,
	}
	session.mu.Unlock()

	// Call retryPending
	session.retryPending()

	// Verify session is cleaned up
	session.mu.RLock()
	isOpen := session.isOpen
	session.mu.RUnlock()

	if isOpen {
		t.Error("session should be closed after MaxRetries exceeded")
	}
}

// TestRetryPending_ConcurrentSafe verifies retryPending is safe under concurrent access.
func TestRetryPending_ConcurrentSafe(t *testing.T) {
	session := newTestSessionForRetry(t)
	defer session.Cleanup()

	// Add a pending message
	msgID := make([]byte, 16)
	rand.Read(msgID)

	session.mu.Lock()
	session.pendingAcks[hex.EncodeToString(msgID)] = &PendingMessage{
		ID:        msgID,
		Plaintext: []byte("test"),
		SentAt:    time.Now(),
		Retries:   0,
	}
	session.mu.Unlock()

	// Call retryPending concurrently
	done := make(chan bool, 5)
	for i := 0; i < 5; i++ {
		go func() {
			session.retryPending()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 5; i++ {
		<-done
	}

	// Session should still be open (retries < MaxRetries)
	session.mu.RLock()
	isOpen := session.isOpen
	session.mu.RUnlock()

	if !isOpen {
		t.Error("session should remain open after concurrent retries")
	}
}

// Helper function to create a test session for retry tests.
func newTestSessionForRetry(t *testing.T) *ChatSession {
	t.Helper()
	return newTestSessionForRetryWithWriter(t, func(env *pb.ChatEnvelope) error {
		return nil
	})
}

// Helper function to create a test session with cleanup callback.
func newTestSessionForRetryWithCleanupCallback(t *testing.T, onCleanup func()) *ChatSession {
	t.Helper()

	sessionID := make([]byte, 16)
	chatKey := make([]byte, ChatKeyLength)
	rand.Read(sessionID)
	rand.Read(chatKey)

	return &ChatSession{
		sessionID:     sessionID,
		chatKey:       chatKey,
		messages:      make([]*StoredMessage, 0),
		pendingAcks:   make(map[string]*PendingMessage),
		isOpen:        true,
		lastActivity:  time.Now(),
		writeEnvelope: func(env *pb.ChatEnvelope) error { return nil },
		onCleanup:     onCleanup,
	}
}

// Helper function to create a test session with a custom envelope writer.
func newTestSessionForRetryWithWriter(t *testing.T, writer func(*pb.ChatEnvelope) error) *ChatSession {
	t.Helper()

	sessionID := make([]byte, 16)
	chatKey := make([]byte, ChatKeyLength)
	rand.Read(sessionID)
	rand.Read(chatKey)

	return &ChatSession{
		sessionID:     sessionID,
		chatKey:       chatKey,
		messages:      make([]*StoredMessage, 0),
		pendingAcks:   make(map[string]*PendingMessage),
		isOpen:        true,
		lastActivity:  time.Now(),
		writeEnvelope: writer,
	}
}

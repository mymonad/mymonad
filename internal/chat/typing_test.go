package chat

import (
	"crypto/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
)

// TestSendTyping_SendsEnvelope verifies that SendTyping sends the correct envelope.
func TestSendTyping_SendsEnvelope(t *testing.T) {
	var sentEnvelope *pb.ChatEnvelope
	session := newTestSessionForTyping(t, func(env *pb.ChatEnvelope) error {
		sentEnvelope = env
		return nil
	})
	defer session.Cleanup()

	// Test sending typing=true
	err := session.SendTyping(true)
	if err != nil {
		t.Fatalf("SendTyping(true) failed: %v", err)
	}

	// Verify envelope was sent
	if sentEnvelope == nil {
		t.Fatal("no envelope was sent")
	}

	// Get the typing payload from envelope
	typing := sentEnvelope.GetTyping()
	if typing == nil {
		t.Fatal("envelope does not contain a typing payload")
	}

	// Verify is_typing is true
	if !typing.IsTyping {
		t.Error("expected IsTyping to be true")
	}

	// Reset and test sending typing=false
	sentEnvelope = nil
	err = session.SendTyping(false)
	if err != nil {
		t.Fatalf("SendTyping(false) failed: %v", err)
	}

	// Verify envelope was sent
	if sentEnvelope == nil {
		t.Fatal("no envelope was sent for typing=false")
	}

	// Get the typing payload from envelope
	typing = sentEnvelope.GetTyping()
	if typing == nil {
		t.Fatal("envelope does not contain a typing payload")
	}

	// Verify is_typing is false
	if typing.IsTyping {
		t.Error("expected IsTyping to be false")
	}
}

// TestSendTyping_RejectsClosedSession verifies that SendTyping fails on closed session.
func TestSendTyping_RejectsClosedSession(t *testing.T) {
	session := newTestSessionForTyping(t, func(env *pb.ChatEnvelope) error {
		return nil
	})

	// Close the session
	session.Cleanup()

	// Attempt to send typing
	err := session.SendTyping(true)
	if err == nil {
		t.Fatal("expected error for closed session, got nil")
	}

	// Verify error indicates session is closed
	if !strings.Contains(err.Error(), "closed") {
		t.Errorf("error should mention closed session, got: %v", err)
	}
}

// TestSendTyping_WriteEnvelopeError verifies that write errors are propagated.
func TestSendTyping_WriteEnvelopeError(t *testing.T) {
	expectedErr := "network error"
	session := newTestSessionForTyping(t, func(env *pb.ChatEnvelope) error {
		return &mockError{msg: expectedErr}
	})
	defer session.Cleanup()

	err := session.SendTyping(true)
	if err == nil {
		t.Fatal("expected error when writeEnvelope fails")
	}

	if !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("error should contain %q, got: %v", expectedErr, err)
	}
}

// TestSendTyping_ConcurrentSafe verifies that SendTyping is safe under concurrent access.
func TestSendTyping_ConcurrentSafe(t *testing.T) {
	var count int32
	session := newTestSessionForTyping(t, func(env *pb.ChatEnvelope) error {
		atomic.AddInt32(&count, 1)
		return nil
	})
	defer session.Cleanup()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(isTyping bool) {
			defer wg.Done()
			_ = session.SendTyping(isTyping)
		}(i%2 == 0)
	}

	wg.Wait()

	// All 10 calls should have sent envelopes
	if atomic.LoadInt32(&count) != 10 {
		t.Errorf("expected 10 envelopes sent, got %d", count)
	}
}

// TestHandleTyping_UpdatesState verifies that handleTyping updates the peerTyping state.
func TestHandleTyping_UpdatesState(t *testing.T) {
	session := newTestSessionForTyping(t, func(env *pb.ChatEnvelope) error {
		return nil
	})
	defer session.Cleanup()

	// Initially peerTyping should be false
	session.mu.RLock()
	if session.peerTyping {
		session.mu.RUnlock()
		t.Error("peerTyping should initially be false")
	}
	session.mu.RUnlock()

	// Handle typing=true
	session.handleTyping(&pb.ChatTyping{IsTyping: true})

	session.mu.RLock()
	if !session.peerTyping {
		session.mu.RUnlock()
		t.Error("peerTyping should be true after handleTyping(true)")
	}
	session.mu.RUnlock()

	// Handle typing=false
	session.handleTyping(&pb.ChatTyping{IsTyping: false})

	session.mu.RLock()
	if session.peerTyping {
		session.mu.RUnlock()
		t.Error("peerTyping should be false after handleTyping(false)")
	}
	session.mu.RUnlock()
}

// TestHandleTyping_UpdatesLastActivity verifies that handleTyping updates lastActivity.
func TestHandleTyping_UpdatesLastActivity(t *testing.T) {
	session := newTestSessionForTyping(t, func(env *pb.ChatEnvelope) error {
		return nil
	})
	defer session.Cleanup()

	// Set old lastActivity
	oldTime := time.Now().Add(-time.Hour)
	session.mu.Lock()
	session.lastActivity = oldTime
	session.mu.Unlock()

	// Handle typing
	session.handleTyping(&pb.ChatTyping{IsTyping: true})

	// Verify lastActivity was updated
	session.mu.RLock()
	defer session.mu.RUnlock()

	if session.lastActivity.Before(time.Now().Add(-time.Second)) {
		t.Error("lastActivity was not updated")
	}
	if !session.lastActivity.After(oldTime) {
		t.Error("lastActivity should be newer than the old time")
	}
}

// TestHandleTyping_CallsCallback verifies that handleTyping calls the onTyping callback.
func TestHandleTyping_CallsCallback(t *testing.T) {
	var callbackCalled bool
	var callbackValue bool
	var mu sync.Mutex

	session := newTestSessionForTyping(t, func(env *pb.ChatEnvelope) error {
		return nil
	})
	defer session.Cleanup()

	session.onTyping = func(isTyping bool) {
		mu.Lock()
		callbackCalled = true
		callbackValue = isTyping
		mu.Unlock()
	}

	// Handle typing=true
	session.handleTyping(&pb.ChatTyping{IsTyping: true})

	mu.Lock()
	if !callbackCalled {
		mu.Unlock()
		t.Error("onTyping callback should have been called")
	}
	if !callbackValue {
		mu.Unlock()
		t.Error("onTyping callback should have received true")
	}
	mu.Unlock()

	// Reset and test with false
	mu.Lock()
	callbackCalled = false
	callbackValue = true
	mu.Unlock()

	session.handleTyping(&pb.ChatTyping{IsTyping: false})

	mu.Lock()
	defer mu.Unlock()
	if !callbackCalled {
		t.Error("onTyping callback should have been called for false")
	}
	if callbackValue {
		t.Error("onTyping callback should have received false")
	}
}

// TestHandleTyping_NoCallbackDoesNotPanic verifies handleTyping works without callback.
func TestHandleTyping_NoCallbackDoesNotPanic(t *testing.T) {
	session := newTestSessionForTyping(t, func(env *pb.ChatEnvelope) error {
		return nil
	})
	defer session.Cleanup()

	// Ensure onTyping is nil
	session.onTyping = nil

	// Should not panic
	session.handleTyping(&pb.ChatTyping{IsTyping: true})

	// Verify state was still updated
	session.mu.RLock()
	defer session.mu.RUnlock()
	if !session.peerTyping {
		t.Error("peerTyping should be true even without callback")
	}
}

// TestHandleTyping_AutoClearsAfterTimeout verifies that typing auto-clears after timeout.
func TestHandleTyping_AutoClearsAfterTimeout(t *testing.T) {
	session := newTestSessionForTyping(t, func(env *pb.ChatEnvelope) error {
		return nil
	})
	defer session.Cleanup()

	var callbackCalled int32
	session.onTyping = func(isTyping bool) {
		if !isTyping {
			atomic.AddInt32(&callbackCalled, 1)
		}
	}

	// Handle typing=true
	session.handleTyping(&pb.ChatTyping{IsTyping: true})

	// Verify typing is true
	session.mu.RLock()
	if !session.peerTyping {
		session.mu.RUnlock()
		t.Fatal("peerTyping should be true initially")
	}
	session.mu.RUnlock()

	// Wait for timeout (with some buffer)
	time.Sleep(TypingTimeout + 100*time.Millisecond)

	// Verify typing was auto-cleared
	session.mu.RLock()
	if session.peerTyping {
		session.mu.RUnlock()
		t.Error("peerTyping should be false after timeout")
	}
	session.mu.RUnlock()

	// Verify callback was called
	if atomic.LoadInt32(&callbackCalled) != 1 {
		t.Errorf("onTyping(false) callback should have been called once, got %d", callbackCalled)
	}
}

// TestHandleTyping_TimeoutResetByNewTyping verifies that new typing resets the timeout.
func TestHandleTyping_TimeoutResetByNewTyping(t *testing.T) {
	session := newTestSessionForTyping(t, func(env *pb.ChatEnvelope) error {
		return nil
	})
	defer session.Cleanup()

	// Handle typing=true
	session.handleTyping(&pb.ChatTyping{IsTyping: true})

	// Wait partial timeout
	time.Sleep(TypingTimeout / 2)

	// Send another typing=true to reset the timeout
	session.handleTyping(&pb.ChatTyping{IsTyping: true})

	// Wait another partial timeout (should still be typing)
	time.Sleep(TypingTimeout / 2)

	// Verify still typing (timeout was reset)
	session.mu.RLock()
	if !session.peerTyping {
		session.mu.RUnlock()
		t.Error("peerTyping should still be true as timeout was reset")
	}
	session.mu.RUnlock()

	// Now wait for full timeout from the second typing
	time.Sleep(TypingTimeout/2 + 100*time.Millisecond)

	// Now it should be cleared
	session.mu.RLock()
	defer session.mu.RUnlock()
	if session.peerTyping {
		t.Error("peerTyping should be false after full timeout")
	}
}

// TestHandleTyping_StoppedTypingNoAutoTimeout verifies no auto-clear for typing=false.
func TestHandleTyping_StoppedTypingNoAutoTimeout(t *testing.T) {
	session := newTestSessionForTyping(t, func(env *pb.ChatEnvelope) error {
		return nil
	})
	defer session.Cleanup()

	var autoClearCalled int32
	session.onTyping = func(isTyping bool) {
		if !isTyping {
			atomic.AddInt32(&autoClearCalled, 1)
		}
	}

	// Handle typing=false (user explicitly stopped typing)
	session.handleTyping(&pb.ChatTyping{IsTyping: false})

	// Verify typing is false
	session.mu.RLock()
	if session.peerTyping {
		session.mu.RUnlock()
		t.Error("peerTyping should be false")
	}
	session.mu.RUnlock()

	// Wait for what would be the timeout
	time.Sleep(TypingTimeout + 100*time.Millisecond)

	// Callback should have been called only once (from handleTyping)
	if atomic.LoadInt32(&autoClearCalled) != 1 {
		t.Errorf("onTyping(false) should be called once, got %d", autoClearCalled)
	}
}

// TestHandleTyping_ConcurrentSafe verifies handleTyping is safe under concurrent access.
func TestHandleTyping_ConcurrentSafe(t *testing.T) {
	session := newTestSessionForTyping(t, func(env *pb.ChatEnvelope) error {
		return nil
	})
	defer session.Cleanup()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(isTyping bool) {
			defer wg.Done()
			session.handleTyping(&pb.ChatTyping{IsTyping: isTyping})
		}(i%2 == 0)
	}

	wg.Wait()
	// Should not have panicked
}

// TestTypingTimeout_Constant verifies the TypingTimeout constant is set correctly.
func TestTypingTimeout_Constant(t *testing.T) {
	expected := 5 * time.Second
	if TypingTimeout != expected {
		t.Errorf("TypingTimeout should be %v, got %v", expected, TypingTimeout)
	}
}

// mockError is a simple error type for testing.
type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}

// Helper function to create a test session for typing tests.
func newTestSessionForTyping(t *testing.T, writer func(*pb.ChatEnvelope) error) *ChatSession {
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
		peerTyping:    false,
		lastActivity:  time.Now(),
		writeEnvelope: writer,
	}

	return session
}

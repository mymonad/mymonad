// Package protocol implements the MyMonad handshake protocol for agent matching.
package protocol

import (
	"crypto/ed25519"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// ============================================================================
// ChatMessage Tests
// ============================================================================

func TestNewChatMessage(t *testing.T) {
	peerID := generateTestPeerID(t)
	content := []byte("Hello, this is an encrypted message")

	t.Run("creates valid message with content", func(t *testing.T) {
		msg := NewChatMessage(peerID, content)

		if msg == nil {
			t.Fatal("expected non-nil message")
		}
		if msg.PeerID != peerID {
			t.Errorf("expected peerID %v, got %v", peerID, msg.PeerID)
		}
		if string(msg.Content) != string(content) {
			t.Error("expected content to match")
		}
		if msg.ID == "" {
			t.Error("expected non-empty message ID")
		}
		if msg.Timestamp.IsZero() {
			t.Error("expected non-zero timestamp")
		}
		if msg.Signature != nil {
			t.Error("expected nil signature before Sign()")
		}
	})

	t.Run("each message has unique ID", func(t *testing.T) {
		msg1 := NewChatMessage(peerID, content)
		msg2 := NewChatMessage(peerID, content)

		if msg1.ID == msg2.ID {
			t.Error("two messages should have different IDs")
		}
	})

	t.Run("timestamp is recent", func(t *testing.T) {
		msg := NewChatMessage(peerID, content)

		if time.Since(msg.Timestamp) > time.Second {
			t.Errorf("timestamp should be recent, got %v", msg.Timestamp)
		}
	})

	t.Run("handles empty content", func(t *testing.T) {
		msg := NewChatMessage(peerID, []byte{})

		if msg == nil {
			t.Fatal("expected non-nil message for empty content")
		}
		if len(msg.Content) != 0 {
			t.Error("expected empty content")
		}
	})

	t.Run("handles nil content", func(t *testing.T) {
		msg := NewChatMessage(peerID, nil)

		if msg == nil {
			t.Fatal("expected non-nil message for nil content")
		}
	})
}

func TestChatMessageSign(t *testing.T) {
	peerID := generateTestPeerID(t)
	_, priv := generateTestKeyPair(t)
	content := []byte("Hello, this is an encrypted message")

	t.Run("signs message successfully", func(t *testing.T) {
		msg := NewChatMessage(peerID, content)

		err := msg.Sign(priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(msg.Signature) != ed25519.SignatureSize {
			t.Errorf("expected signature length %d, got %d", ed25519.SignatureSize, len(msg.Signature))
		}
	})

	t.Run("signature is deterministic for same content", func(t *testing.T) {
		msg := NewChatMessage(peerID, content)

		err := msg.Sign(priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sig1 := make([]byte, len(msg.Signature))
		copy(sig1, msg.Signature)

		// Sign again with same key
		msg.Signature = nil
		err = msg.Sign(priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if string(msg.Signature) != string(sig1) {
			t.Error("signature should be deterministic for same content")
		}
	})
}

func TestChatMessageVerify(t *testing.T) {
	peerID := generateTestPeerID(t)
	pub, priv := generateTestKeyPair(t)
	pub2, _ := generateTestKeyPair(t) // Different key pair
	content := []byte("Hello, this is an encrypted message")

	t.Run("verifies valid signature", func(t *testing.T) {
		msg := NewChatMessage(peerID, content)
		_ = msg.Sign(priv)

		err := msg.Verify(pub)
		if err != nil {
			t.Fatalf("expected valid signature, got error: %v", err)
		}
	})

	t.Run("rejects invalid signature", func(t *testing.T) {
		msg := NewChatMessage(peerID, content)
		_ = msg.Sign(priv)

		// Verify with different key
		err := msg.Verify(pub2)
		if err == nil {
			t.Error("expected error for invalid signature")
		}
	})

	t.Run("rejects tampered message", func(t *testing.T) {
		msg := NewChatMessage(peerID, content)
		_ = msg.Sign(priv)

		// Tamper with content
		msg.Content = []byte("tampered content")

		err := msg.Verify(pub)
		if err == nil {
			t.Error("expected error for tampered message")
		}
	})

	t.Run("rejects unsigned message", func(t *testing.T) {
		msg := NewChatMessage(peerID, content)

		err := msg.Verify(pub)
		if err == nil {
			t.Error("expected error for unsigned message")
		}
	})
}

func TestChatMessageBytesToSign(t *testing.T) {
	peerID := generateTestPeerID(t)
	content := []byte("Hello, this is an encrypted message")

	msg := NewChatMessage(peerID, content)

	// Calling BytesToSign should return consistent bytes
	bytes1 := msg.BytesToSign()
	bytes2 := msg.BytesToSign()

	if string(bytes1) != string(bytes2) {
		t.Error("BytesToSign should return consistent results")
	}

	if len(bytes1) == 0 {
		t.Error("BytesToSign should return non-empty bytes")
	}
}

// ============================================================================
// ChatSession Tests
// ============================================================================

func TestNewChatSession(t *testing.T) {
	peerA := peer.ID("12D3KooWPeerA123456789")
	peerB := peer.ID("12D3KooWPeerB123456789")

	t.Run("creates valid session with peers", func(t *testing.T) {
		session := NewChatSession(peerA, peerB)

		if session == nil {
			t.Fatal("expected non-nil session")
		}
		if session.SessionID == "" {
			t.Error("expected non-empty session ID")
		}
		if session.PeerA != peerA {
			t.Errorf("expected peerA %v, got %v", peerA, session.PeerA)
		}
		if session.PeerB != peerB {
			t.Errorf("expected peerB %v, got %v", peerB, session.PeerB)
		}
		if session.StartTime.IsZero() {
			t.Error("expected non-zero start time")
		}
		if !session.Active {
			t.Error("expected session to be active")
		}
		if len(session.Messages) != 0 {
			t.Error("expected empty messages initially")
		}
	})

	t.Run("each session has unique ID", func(t *testing.T) {
		session1 := NewChatSession(peerA, peerB)
		session2 := NewChatSession(peerA, peerB)

		if session1.SessionID == session2.SessionID {
			t.Error("two sessions should have different IDs")
		}
	})

	t.Run("start time is recent", func(t *testing.T) {
		session := NewChatSession(peerA, peerB)

		if time.Since(session.StartTime) > time.Second {
			t.Errorf("start time should be recent, got %v", session.StartTime)
		}
	})
}

func TestChatSessionAddMessage(t *testing.T) {
	peerA := peer.ID("12D3KooWPeerA123456789")
	peerB := peer.ID("12D3KooWPeerB123456789")
	content := []byte("Hello!")

	t.Run("adds message to active session", func(t *testing.T) {
		session := NewChatSession(peerA, peerB)
		msg := NewChatMessage(peerA, content)

		err := session.AddMessage(msg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(session.Messages) != 1 {
			t.Errorf("expected 1 message, got %d", len(session.Messages))
		}
		if session.Messages[0] != msg {
			t.Error("expected message to be added")
		}
	})

	t.Run("adds multiple messages in order", func(t *testing.T) {
		session := NewChatSession(peerA, peerB)
		msg1 := NewChatMessage(peerA, []byte("Message 1"))
		msg2 := NewChatMessage(peerB, []byte("Message 2"))
		msg3 := NewChatMessage(peerA, []byte("Message 3"))

		_ = session.AddMessage(msg1)
		_ = session.AddMessage(msg2)
		_ = session.AddMessage(msg3)

		if len(session.Messages) != 3 {
			t.Fatalf("expected 3 messages, got %d", len(session.Messages))
		}
		if session.Messages[0] != msg1 {
			t.Error("expected msg1 at index 0")
		}
		if session.Messages[1] != msg2 {
			t.Error("expected msg2 at index 1")
		}
		if session.Messages[2] != msg3 {
			t.Error("expected msg3 at index 2")
		}
	})

	t.Run("rejects message when session is inactive", func(t *testing.T) {
		session := NewChatSession(peerA, peerB)
		session.End() // Mark as inactive

		msg := NewChatMessage(peerA, content)
		err := session.AddMessage(msg)
		if err == nil {
			t.Error("expected error for inactive session")
		}
	})

	t.Run("rejects nil message", func(t *testing.T) {
		session := NewChatSession(peerA, peerB)

		err := session.AddMessage(nil)
		if err == nil {
			t.Error("expected error for nil message")
		}
	})
}

func TestChatSessionEnd(t *testing.T) {
	peerA := peer.ID("12D3KooWPeerA123456789")
	peerB := peer.ID("12D3KooWPeerB123456789")

	t.Run("marks session as inactive", func(t *testing.T) {
		session := NewChatSession(peerA, peerB)

		if !session.Active {
			t.Error("session should be active initially")
		}

		session.End()

		if session.Active {
			t.Error("session should be inactive after End()")
		}
	})

	t.Run("end is idempotent", func(t *testing.T) {
		session := NewChatSession(peerA, peerB)

		session.End()
		session.End() // Should not panic
		session.End()

		if session.Active {
			t.Error("session should remain inactive")
		}
	})

	t.Run("preserves messages after end", func(t *testing.T) {
		session := NewChatSession(peerA, peerB)
		msg := NewChatMessage(peerA, []byte("Hello!"))
		_ = session.AddMessage(msg)

		session.End()

		if len(session.Messages) != 1 {
			t.Error("messages should be preserved after End()")
		}
	})
}

func TestChatSessionIsActive(t *testing.T) {
	peerA := peer.ID("12D3KooWPeerA123456789")
	peerB := peer.ID("12D3KooWPeerB123456789")

	t.Run("returns true for active session", func(t *testing.T) {
		session := NewChatSession(peerA, peerB)

		if !session.IsActive() {
			t.Error("expected IsActive() to return true")
		}
	})

	t.Run("returns false for ended session", func(t *testing.T) {
		session := NewChatSession(peerA, peerB)
		session.End()

		if session.IsActive() {
			t.Error("expected IsActive() to return false after End()")
		}
	})
}

func TestChatSessionMessageCount(t *testing.T) {
	peerA := peer.ID("12D3KooWPeerA123456789")
	peerB := peer.ID("12D3KooWPeerB123456789")

	t.Run("returns correct count", func(t *testing.T) {
		session := NewChatSession(peerA, peerB)

		if session.MessageCount() != 0 {
			t.Error("expected 0 messages initially")
		}

		_ = session.AddMessage(NewChatMessage(peerA, []byte("1")))
		_ = session.AddMessage(NewChatMessage(peerB, []byte("2")))

		if session.MessageCount() != 2 {
			t.Errorf("expected 2 messages, got %d", session.MessageCount())
		}
	})
}

// ============================================================================
// ChatControlType Tests
// ============================================================================

func TestChatControlTypeString(t *testing.T) {
	tests := []struct {
		controlType ChatControlType
		expected    string
	}{
		{ChatStart, "Start"},
		{ChatEnd, "End"},
		{ChatTimeout, "Timeout"},
		{ChatApproval, "Approval"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.controlType.String() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tt.controlType.String())
			}
		})
	}

	t.Run("unknown type", func(t *testing.T) {
		unknown := ChatControlType(99)
		result := unknown.String()
		if result == "" {
			t.Error("unknown type should return non-empty string")
		}
	})
}

// ============================================================================
// ChatControl Tests
// ============================================================================

func TestNewChatControl(t *testing.T) {
	peerID := generateTestPeerID(t)
	sessionID := "test-session-123"

	t.Run("creates valid chat control", func(t *testing.T) {
		ctrl := NewChatControl(ChatStart, sessionID, peerID)

		if ctrl == nil {
			t.Fatal("expected non-nil control")
		}
		if ctrl.Type != ChatStart {
			t.Errorf("expected type ChatStart, got %v", ctrl.Type)
		}
		if ctrl.SessionID != sessionID {
			t.Errorf("expected sessionID %q, got %q", sessionID, ctrl.SessionID)
		}
		if ctrl.PeerID != peerID {
			t.Errorf("expected peerID %v, got %v", peerID, ctrl.PeerID)
		}
		if ctrl.Timestamp.IsZero() {
			t.Error("expected non-zero timestamp")
		}
		if ctrl.Signature != nil {
			t.Error("expected nil signature before Sign()")
		}
	})

	t.Run("creates different control types", func(t *testing.T) {
		types := []ChatControlType{ChatStart, ChatEnd, ChatTimeout, ChatApproval}

		for _, ct := range types {
			ctrl := NewChatControl(ct, sessionID, peerID)
			if ctrl.Type != ct {
				t.Errorf("expected type %v, got %v", ct, ctrl.Type)
			}
		}
	})

	t.Run("timestamp is recent", func(t *testing.T) {
		ctrl := NewChatControl(ChatStart, sessionID, peerID)

		if time.Since(ctrl.Timestamp) > time.Second {
			t.Errorf("timestamp should be recent, got %v", ctrl.Timestamp)
		}
	})
}

func TestChatControlSign(t *testing.T) {
	peerID := generateTestPeerID(t)
	_, priv := generateTestKeyPair(t)
	sessionID := "test-session-123"

	t.Run("signs control successfully", func(t *testing.T) {
		ctrl := NewChatControl(ChatStart, sessionID, peerID)

		err := ctrl.Sign(priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(ctrl.Signature) != ed25519.SignatureSize {
			t.Errorf("expected signature length %d, got %d", ed25519.SignatureSize, len(ctrl.Signature))
		}
	})

	t.Run("signature is deterministic for same content", func(t *testing.T) {
		ctrl := NewChatControl(ChatEnd, sessionID, peerID)

		err := ctrl.Sign(priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sig1 := make([]byte, len(ctrl.Signature))
		copy(sig1, ctrl.Signature)

		// Sign again with same key
		ctrl.Signature = nil
		err = ctrl.Sign(priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if string(ctrl.Signature) != string(sig1) {
			t.Error("signature should be deterministic for same content")
		}
	})
}

func TestChatControlVerify(t *testing.T) {
	peerID := generateTestPeerID(t)
	pub, priv := generateTestKeyPair(t)
	pub2, _ := generateTestKeyPair(t) // Different key pair
	sessionID := "test-session-123"

	t.Run("verifies valid signature", func(t *testing.T) {
		ctrl := NewChatControl(ChatApproval, sessionID, peerID)
		_ = ctrl.Sign(priv)

		err := ctrl.Verify(pub)
		if err != nil {
			t.Fatalf("expected valid signature, got error: %v", err)
		}
	})

	t.Run("rejects invalid signature", func(t *testing.T) {
		ctrl := NewChatControl(ChatApproval, sessionID, peerID)
		_ = ctrl.Sign(priv)

		// Verify with different key
		err := ctrl.Verify(pub2)
		if err == nil {
			t.Error("expected error for invalid signature")
		}
	})

	t.Run("rejects tampered control", func(t *testing.T) {
		ctrl := NewChatControl(ChatStart, sessionID, peerID)
		_ = ctrl.Sign(priv)

		// Tamper with session ID
		ctrl.SessionID = "tampered-session"

		err := ctrl.Verify(pub)
		if err == nil {
			t.Error("expected error for tampered control")
		}
	})

	t.Run("rejects tampered control type", func(t *testing.T) {
		ctrl := NewChatControl(ChatStart, sessionID, peerID)
		_ = ctrl.Sign(priv)

		// Tamper with type
		ctrl.Type = ChatEnd

		err := ctrl.Verify(pub)
		if err == nil {
			t.Error("expected error for tampered control type")
		}
	})

	t.Run("rejects unsigned control", func(t *testing.T) {
		ctrl := NewChatControl(ChatApproval, sessionID, peerID)

		err := ctrl.Verify(pub)
		if err == nil {
			t.Error("expected error for unsigned control")
		}
	})
}

func TestChatControlBytesToSign(t *testing.T) {
	peerID := generateTestPeerID(t)
	sessionID := "test-session-123"

	ctrl := NewChatControl(ChatStart, sessionID, peerID)

	// Calling BytesToSign should return consistent bytes
	bytes1 := ctrl.BytesToSign()
	bytes2 := ctrl.BytesToSign()

	if string(bytes1) != string(bytes2) {
		t.Error("BytesToSign should return consistent results")
	}

	if len(bytes1) == 0 {
		t.Error("BytesToSign should return non-empty bytes")
	}
}

// ============================================================================
// Integration Tests
// ============================================================================

func TestChatMessageSessionFlow(t *testing.T) {
	// Simulate a full chat session between two peers
	peerA := peer.ID("12D3KooWPeerA123456789")
	peerB := peer.ID("12D3KooWPeerB123456789")
	pubA, privA := generateTestKeyPair(t)
	pubB, privB := generateTestKeyPair(t)

	// Step 1: Create a chat session
	session := NewChatSession(peerA, peerB)
	if session == nil {
		t.Fatal("failed to create session")
	}

	// Step 2: PeerA sends start control
	startCtrl := NewChatControl(ChatStart, session.SessionID, peerA)
	if err := startCtrl.Sign(privA); err != nil {
		t.Fatalf("failed to sign start control: %v", err)
	}
	if err := startCtrl.Verify(pubA); err != nil {
		t.Fatalf("failed to verify start control: %v", err)
	}

	// Step 3: Exchange messages
	msg1 := NewChatMessage(peerA, []byte("Hi, nice to meet you!"))
	if err := msg1.Sign(privA); err != nil {
		t.Fatalf("failed to sign msg1: %v", err)
	}
	if err := msg1.Verify(pubA); err != nil {
		t.Fatalf("failed to verify msg1: %v", err)
	}
	if err := session.AddMessage(msg1); err != nil {
		t.Fatalf("failed to add msg1: %v", err)
	}

	msg2 := NewChatMessage(peerB, []byte("Hello! Nice to meet you too!"))
	if err := msg2.Sign(privB); err != nil {
		t.Fatalf("failed to sign msg2: %v", err)
	}
	if err := msg2.Verify(pubB); err != nil {
		t.Fatalf("failed to verify msg2: %v", err)
	}
	if err := session.AddMessage(msg2); err != nil {
		t.Fatalf("failed to add msg2: %v", err)
	}

	// Step 4: PeerA wants to proceed (approval)
	approvalA := NewChatControl(ChatApproval, session.SessionID, peerA)
	if err := approvalA.Sign(privA); err != nil {
		t.Fatalf("failed to sign approvalA: %v", err)
	}
	if err := approvalA.Verify(pubA); err != nil {
		t.Fatalf("failed to verify approvalA: %v", err)
	}

	// Step 5: PeerB also approves
	approvalB := NewChatControl(ChatApproval, session.SessionID, peerB)
	if err := approvalB.Sign(privB); err != nil {
		t.Fatalf("failed to sign approvalB: %v", err)
	}
	if err := approvalB.Verify(pubB); err != nil {
		t.Fatalf("failed to verify approvalB: %v", err)
	}

	// Verify session state
	if session.MessageCount() != 2 {
		t.Errorf("expected 2 messages, got %d", session.MessageCount())
	}
	if !session.IsActive() {
		t.Error("session should still be active")
	}

	// Step 6: End the session
	session.End()
	if session.IsActive() {
		t.Error("session should be inactive after End()")
	}
}

func TestChatSessionRejectionFlow(t *testing.T) {
	// Simulate a chat session where one peer rejects (ends chat early)
	peerA := peer.ID("12D3KooWPeerA123456789")
	peerB := peer.ID("12D3KooWPeerB123456789")
	_, privA := generateTestKeyPair(t)
	pubB, privB := generateTestKeyPair(t)

	// Create session and exchange a message
	session := NewChatSession(peerA, peerB)
	msg := NewChatMessage(peerA, []byte("Hi!"))
	_ = msg.Sign(privA)
	_ = session.AddMessage(msg)

	// PeerB decides to end the chat (rejection)
	endCtrl := NewChatControl(ChatEnd, session.SessionID, peerB)
	if err := endCtrl.Sign(privB); err != nil {
		t.Fatalf("failed to sign end control: %v", err)
	}
	if err := endCtrl.Verify(pubB); err != nil {
		t.Fatalf("failed to verify end control: %v", err)
	}

	// End the session
	session.End()

	// No more messages can be added
	newMsg := NewChatMessage(peerA, []byte("Wait!"))
	err := session.AddMessage(newMsg)
	if err == nil {
		t.Error("should not be able to add messages to ended session")
	}
}

func TestChatTimeoutFlow(t *testing.T) {
	// Simulate a chat session timeout
	peerA := peer.ID("12D3KooWPeerA123456789")
	peerB := peer.ID("12D3KooWPeerB123456789")
	pub, priv := generateTestKeyPair(t)

	session := NewChatSession(peerA, peerB)

	// System sends timeout control
	timeoutCtrl := NewChatControl(ChatTimeout, session.SessionID, peerA)
	if err := timeoutCtrl.Sign(priv); err != nil {
		t.Fatalf("failed to sign timeout control: %v", err)
	}
	if err := timeoutCtrl.Verify(pub); err != nil {
		t.Fatalf("failed to verify timeout control: %v", err)
	}

	// Session should be ended on timeout
	session.End()

	if session.IsActive() {
		t.Error("session should be inactive after timeout")
	}
}

// ============================================================================
// Concurrent Tests
// ============================================================================

func TestChatSessionConcurrentAddMessage(t *testing.T) {
	peerA := peer.ID("12D3KooWPeerA123456789")
	peerB := peer.ID("12D3KooWPeerB123456789")

	session := NewChatSession(peerA, peerB)

	var wg sync.WaitGroup
	numGoroutines := 100
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			msg := NewChatMessage(peerA, []byte("message"))
			if err := session.AddMessage(msg); err != nil {
				errChan <- err
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Collect errors
	for err := range errChan {
		t.Errorf("unexpected error: %v", err)
	}

	// All messages should be added
	if session.MessageCount() != numGoroutines {
		t.Errorf("expected %d messages, got %d", numGoroutines, session.MessageCount())
	}
}

func TestChatSessionConcurrentEndAndAddMessage(t *testing.T) {
	peerA := peer.ID("12D3KooWPeerA123456789")
	peerB := peer.ID("12D3KooWPeerB123456789")

	session := NewChatSession(peerA, peerB)

	var wg sync.WaitGroup

	// Some goroutines try to add messages
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			msg := NewChatMessage(peerA, []byte("message"))
			_ = session.AddMessage(msg) // May or may not succeed
		}()
	}

	// Some goroutines try to end the session
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			session.End()
		}()
	}

	wg.Wait()

	// Session should definitely be inactive now
	if session.IsActive() {
		t.Error("session should be inactive after End()")
	}
}

func TestChatSessionConcurrentRead(t *testing.T) {
	peerA := peer.ID("12D3KooWPeerA123456789")
	peerB := peer.ID("12D3KooWPeerB123456789")

	session := NewChatSession(peerA, peerB)

	// Add some messages first
	for i := 0; i < 10; i++ {
		msg := NewChatMessage(peerA, []byte("message"))
		_ = session.AddMessage(msg)
	}

	var wg sync.WaitGroup
	numReaders := 50

	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = session.IsActive()
			_ = session.MessageCount()
		}()
	}

	wg.Wait()
}

func TestChatMessageConcurrentSignAndVerify(t *testing.T) {
	peerID := generateTestPeerID(t)
	pub, priv := generateTestKeyPair(t)
	content := []byte("test message")

	var wg sync.WaitGroup
	numGoroutines := 50
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			msg := NewChatMessage(peerID, content)
			if err := msg.Sign(priv); err != nil {
				errChan <- err
				return
			}
			if err := msg.Verify(pub); err != nil {
				errChan <- err
				return
			}
		}()
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestChatControlConcurrentSignAndVerify(t *testing.T) {
	peerID := generateTestPeerID(t)
	pub, priv := generateTestKeyPair(t)
	sessionID := "test-session"

	var wg sync.WaitGroup
	numGoroutines := 50
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctrl := NewChatControl(ChatStart, sessionID, peerID)
			if err := ctrl.Sign(priv); err != nil {
				errChan <- err
				return
			}
			if err := ctrl.Verify(pub); err != nil {
				errChan <- err
				return
			}
		}()
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("unexpected error: %v", err)
	}
}

// ============================================================================
// Edge Cases
// ============================================================================

func TestChatMessageWithLargeContent(t *testing.T) {
	peerID := generateTestPeerID(t)
	pub, priv := generateTestKeyPair(t)

	// Create a large message (1MB)
	largeContent := make([]byte, 1<<20)
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}

	msg := NewChatMessage(peerID, largeContent)
	if err := msg.Sign(priv); err != nil {
		t.Fatalf("failed to sign large message: %v", err)
	}
	if err := msg.Verify(pub); err != nil {
		t.Fatalf("failed to verify large message: %v", err)
	}
}

func TestChatSessionWithManyMessages(t *testing.T) {
	peerA := peer.ID("12D3KooWPeerA123456789")
	peerB := peer.ID("12D3KooWPeerB123456789")

	session := NewChatSession(peerA, peerB)

	// Add many messages
	numMessages := 1000
	for i := 0; i < numMessages; i++ {
		sender := peerA
		if i%2 == 1 {
			sender = peerB
		}
		msg := NewChatMessage(sender, []byte("message"))
		if err := session.AddMessage(msg); err != nil {
			t.Fatalf("failed to add message %d: %v", i, err)
		}
	}

	if session.MessageCount() != numMessages {
		t.Errorf("expected %d messages, got %d", numMessages, session.MessageCount())
	}
}

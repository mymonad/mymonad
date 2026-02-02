// Package chat provides encrypted chat functionality for the MyMonad protocol.
// This file implements the ChatSession struct and secure memory cleanup.
package chat

import (
	"encoding/hex"
	"log/slog"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	pb "github.com/mymonad/mymonad/api/proto"
)

// Session-related constants.
const (
	// MaxBufferedMessages is the maximum number of messages stored per session.
	// Oldest messages are evicted when this limit is exceeded.
	MaxBufferedMessages = 100

	// MaxRetries is the maximum number of retry attempts for message delivery.
	// Exceeding this triggers session cleanup.
	MaxRetries = 5
)

// MessageDirection indicates whether a message was sent or received.
type MessageDirection int

const (
	// DirectionSent indicates a message was sent by the local user.
	DirectionSent MessageDirection = iota

	// DirectionReceived indicates a message was received from the peer.
	DirectionReceived
)

// ReceivedMessage represents a message received from a peer.
type ReceivedMessage struct {
	ID        []byte
	Plaintext []byte
	ReceivedAt time.Time
}

// ChatSession represents an active encrypted chat session with a peer.
// All sensitive data (keys, plaintexts) are stored as []byte for secure wiping.
type ChatSession struct {
	mu        sync.RWMutex
	sessionID []byte
	peerID    peer.ID
	chatKey   []byte         // Derived via HKDF
	stream    network.Stream // /mymonad/chat/1.0.0

	// RAM-only message buffer ([]byte for secure wipe)
	messages    []*StoredMessage
	pendingAcks map[string]*PendingMessage // Keyed by message_id hex

	// State
	isOpen       bool
	peerTyping   bool
	lastActivity time.Time

	// Callbacks
	onMessage   func(*ReceivedMessage)
	onTyping    func(bool)
	onDelivered func(messageID []byte)
	onCleanup   func() // Notify parent service

	// writeEnvelope is a function to send a ChatEnvelope over the network.
	// This is injected to allow testing without actual network streams.
	// In production, this wraps protobuf marshaling and stream writing.
	writeEnvelope func(*pb.ChatEnvelope) error
}

// StoredMessage represents a message stored in the session buffer.
type StoredMessage struct {
	ID          []byte
	Plaintext   []byte     // []byte for secure zeroing
	SentAt      time.Time
	DeliveredAt *time.Time // nil until ACK received
	Direction   MessageDirection
}

// PendingMessage represents a message awaiting acknowledgment.
type PendingMessage struct {
	ID        []byte
	Plaintext []byte // []byte for secure zeroing
	SentAt    time.Time
	Retries   int
}

// zeroFill securely wipes a byte slice by setting all bytes to zero.
// This prevents sensitive data from lingering in memory.
func zeroFill(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// retryPending attempts to resend unacknowledged messages.
// It increments the retry counter for each pending message and resends it.
// If MaxRetries is exceeded for any message, the session is cleaned up.
func (s *ChatSession) retryPending() {
	s.mu.Lock()

	// Check if session is still open
	if !s.isOpen {
		s.mu.Unlock()
		return
	}

	// Iterate over pending messages
	for id, pending := range s.pendingAcks {
		pending.Retries++

		if pending.Retries > MaxRetries {
			slog.Error("max retries exceeded, cleaning up session",
				"session_id", hex.EncodeToString(s.sessionID),
				"message_id", id,
			)
			// Release lock before cleanup to avoid deadlock
			s.mu.Unlock()
			s.Cleanup()
			return
		}

		// Resend message using sendEncrypted
		if err := s.sendEncryptedLocked(pending.ID, pending.Plaintext); err != nil {
			slog.Warn("retry failed", "message_id", id, "error", err)
		}
	}

	s.mu.Unlock()
}

// sendEncryptedLocked encrypts and sends a message. Must be called while holding the lock.
// This is used by retryPending to resend messages.
func (s *ChatSession) sendEncryptedLocked(messageID []byte, plaintextBytes []byte) error {
	// Encrypt using chat key
	ciphertext, err := Encrypt(s.chatKey, plaintextBytes)
	if err != nil {
		return err
	}

	// Extract nonce from ciphertext (first 12 bytes)
	nonce := ciphertext[:NonceLength]
	encryptedPayload := ciphertext[NonceLength:]

	// Build and send envelope
	envelope := &pb.ChatEnvelope{
		Payload: &pb.ChatEnvelope_Message{
			Message: &pb.ChatMessage{
				MessageId:  messageID,
				Ciphertext: encryptedPayload,
				Nonce:      nonce,
				Timestamp:  time.Now().UnixMilli(),
			},
		},
	}

	return s.writeEnvelope(envelope)
}

// Cleanup securely wipes all sensitive data and closes the session.
// This function is called by the handshake Session.Cleanup() method.
// It is safe to call multiple times (idempotent).
func (s *ChatSession) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return // Already cleaned up
	}

	// Close stream
	if s.stream != nil {
		s.stream.Close()
		s.stream = nil
	}

	// Wipe key material
	zeroFill(s.chatKey)
	s.chatKey = nil

	// Wipe message buffer
	for _, msg := range s.messages {
		zeroFill(msg.Plaintext)
		zeroFill(msg.ID)
	}
	s.messages = nil

	// Wipe pending messages
	for _, pending := range s.pendingAcks {
		zeroFill(pending.Plaintext)
		zeroFill(pending.ID)
	}
	s.pendingAcks = nil

	// Wipe session ID
	zeroFill(s.sessionID)

	s.isOpen = false

	// Notify parent service
	if s.onCleanup != nil {
		s.onCleanup()
	}
}

// Package chat provides encrypted chat functionality for the MyMonad protocol.
// This file implements the ChatSession struct and secure memory cleanup.
package chat

import (
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
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

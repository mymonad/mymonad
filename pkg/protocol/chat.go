// Package protocol implements the MyMonad handshake protocol for agent matching.
package protocol

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/libp2p/go-libp2p/core/peer"
)

// Chat errors.
var (
	// ErrSessionInactive is returned when attempting to add a message to an inactive session.
	ErrSessionInactive = errors.New("chat: session is inactive")

	// ErrNilMessage is returned when attempting to add a nil message.
	ErrNilMessage = errors.New("chat: message cannot be nil")
)

// ChatControlType identifies the type of chat control message.
type ChatControlType int

const (
	// ChatStart signals the start of a chat session.
	ChatStart ChatControlType = iota
	// ChatEnd signals the end of a chat session.
	ChatEnd
	// ChatTimeout signals a session timeout.
	ChatTimeout
	// ChatApproval signals a user wants to proceed to unmask.
	ChatApproval
)

// String returns a human-readable name for the control type.
func (ct ChatControlType) String() string {
	switch ct {
	case ChatStart:
		return "Start"
	case ChatEnd:
		return "End"
	case ChatTimeout:
		return "Timeout"
	case ChatApproval:
		return "Approval"
	default:
		return fmt.Sprintf("Unknown(%d)", ct)
	}
}

// ChatMessage represents a single chat message in the human chat relay stage.
// Content is encrypted at the application level before being placed here.
type ChatMessage struct {
	// ID is a unique identifier for this message (UUID).
	ID string

	// PeerID is the sender's libp2p peer ID.
	PeerID peer.ID

	// Content is the encrypted message content.
	Content []byte

	// Timestamp is when the message was created.
	Timestamp time.Time

	// Signature is the Ed25519 signature over the message content.
	Signature []byte
}

// NewChatMessage creates a new chat message with a unique ID and current timestamp.
func NewChatMessage(peerID peer.ID, content []byte) *ChatMessage {
	return &ChatMessage{
		ID:        uuid.New().String(),
		PeerID:    peerID,
		Content:   content,
		Timestamp: time.Now().UTC(),
	}
}

// BytesToSign returns the bytes that should be signed for this message.
// This includes ID, peerID, content, and timestamp but NOT the signature.
func (m *ChatMessage) BytesToSign() []byte {
	var buf []byte

	// ID
	buf = append(buf, []byte(m.ID)...)
	buf = append(buf, 0) // separator

	// PeerID
	buf = append(buf, []byte(m.PeerID)...)
	buf = append(buf, 0) // separator

	// Content
	buf = append(buf, m.Content...)
	buf = append(buf, 0) // separator

	// Timestamp as 8-byte big-endian
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(m.Timestamp.Unix()))
	buf = append(buf, timestampBytes...)

	return buf
}

// Sign signs the message with the given Ed25519 private key.
func (m *ChatMessage) Sign(privateKey ed25519.PrivateKey) error {
	m.Signature = ed25519.Sign(privateKey, m.BytesToSign())
	return nil
}

// Verify verifies the message signature using the given Ed25519 public key.
func (m *ChatMessage) Verify(publicKey ed25519.PublicKey) error {
	if len(m.Signature) == 0 {
		return ErrSignatureRequired
	}

	if !ed25519.Verify(publicKey, m.BytesToSign(), m.Signature) {
		return ErrInvalidSignature
	}

	return nil
}

// ChatSession tracks an active chat session between two peers.
// All messages are stored for potential audit purposes.
type ChatSession struct {
	// SessionID is a unique identifier for this session (UUID).
	SessionID string

	// PeerA is the first peer (typically the initiator).
	PeerA peer.ID

	// PeerB is the second peer (typically the responder).
	PeerB peer.ID

	// StartTime is when the session was created.
	StartTime time.Time

	// Messages contains all messages exchanged in this session.
	Messages []*ChatMessage

	// Active indicates if the session is still active.
	Active bool

	// mu protects concurrent access to the session.
	mu sync.RWMutex
}

// NewChatSession creates a new active chat session between two peers.
func NewChatSession(peerA, peerB peer.ID) *ChatSession {
	return &ChatSession{
		SessionID: uuid.New().String(),
		PeerA:     peerA,
		PeerB:     peerB,
		StartTime: time.Now().UTC(),
		Messages:  make([]*ChatMessage, 0),
		Active:    true,
	}
}

// AddMessage adds a message to the session.
// Returns an error if the session is inactive or the message is nil.
func (s *ChatSession) AddMessage(msg *ChatMessage) error {
	if msg == nil {
		return ErrNilMessage
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.Active {
		return ErrSessionInactive
	}

	s.Messages = append(s.Messages, msg)
	return nil
}

// End marks the session as inactive.
// This is idempotent - calling End multiple times has no additional effect.
func (s *ChatSession) End() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Active = false
}

// IsActive returns whether the session is still active.
func (s *ChatSession) IsActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Active
}

// MessageCount returns the number of messages in the session.
func (s *ChatSession) MessageCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.Messages)
}

// ChatControl represents a control message for session management.
// These are used to signal session start, end, timeout, or approval.
type ChatControl struct {
	// Type is the control message type.
	Type ChatControlType

	// SessionID is the session this control message applies to.
	SessionID string

	// PeerID is the sender of this control message.
	PeerID peer.ID

	// Timestamp is when the control message was created.
	Timestamp time.Time

	// Signature is the Ed25519 signature over the control message.
	Signature []byte
}

// NewChatControl creates a new chat control message.
func NewChatControl(controlType ChatControlType, sessionID string, peerID peer.ID) *ChatControl {
	return &ChatControl{
		Type:      controlType,
		SessionID: sessionID,
		PeerID:    peerID,
		Timestamp: time.Now().UTC(),
	}
}

// BytesToSign returns the bytes that should be signed for this control message.
// This includes type, sessionID, peerID, and timestamp but NOT the signature.
func (c *ChatControl) BytesToSign() []byte {
	var buf []byte

	// Type as single byte
	buf = append(buf, byte(c.Type))

	// SessionID
	buf = append(buf, []byte(c.SessionID)...)
	buf = append(buf, 0) // separator

	// PeerID
	buf = append(buf, []byte(c.PeerID)...)
	buf = append(buf, 0) // separator

	// Timestamp as 8-byte big-endian
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(c.Timestamp.Unix()))
	buf = append(buf, timestampBytes...)

	return buf
}

// Sign signs the control message with the given Ed25519 private key.
func (c *ChatControl) Sign(privateKey ed25519.PrivateKey) error {
	c.Signature = ed25519.Sign(privateKey, c.BytesToSign())
	return nil
}

// Verify verifies the control message signature using the given Ed25519 public key.
func (c *ChatControl) Verify(publicKey ed25519.PublicKey) error {
	if len(c.Signature) == 0 {
		return ErrSignatureRequired
	}

	if !ed25519.Verify(publicKey, c.BytesToSign(), c.Signature) {
		return ErrInvalidSignature
	}

	return nil
}

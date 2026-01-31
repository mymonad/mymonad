// Package protocol implements the MyMonad handshake protocol for agent matching.
package protocol

import (
	"errors"
	"fmt"
	"time"
)

// MessageType identifies the type of handshake message.
type MessageType int

const (
	// MsgAttestation is sent during the attestation stage to verify peer legitimacy.
	MsgAttestation MessageType = iota
	// MsgVectorMatch is sent during TEE-based embedding comparison.
	MsgVectorMatch
	// MsgDealBreaker is sent during the deal-breaker question exchange.
	MsgDealBreaker
	// MsgChat is sent during the human chat relay stage.
	MsgChat
	// MsgUnmask is sent during the final identity exchange stage.
	MsgUnmask
)

// String returns a human-readable name for the message type.
func (mt MessageType) String() string {
	switch mt {
	case MsgAttestation:
		return "Attestation"
	case MsgVectorMatch:
		return "VectorMatch"
	case MsgDealBreaker:
		return "DealBreaker"
	case MsgChat:
		return "Chat"
	case MsgUnmask:
		return "Unmask"
	default:
		return fmt.Sprintf("Unknown(%d)", mt)
	}
}

// isValid returns true if the message type is a known valid type.
func (mt MessageType) isValid() bool {
	return mt >= MsgAttestation && mt <= MsgUnmask
}

// Message represents a handshake protocol message.
type Message struct {
	// Type identifies what kind of message this is.
	Type MessageType

	// Payload contains the message-specific data.
	Payload []byte

	// Timestamp records when the message was created.
	Timestamp time.Time

	// Signature contains the cryptographic signature over the message.
	Signature []byte
}

// NewMessage creates a new Message with the given type and payload.
// The timestamp is set to the current time.
func NewMessage(msgType MessageType, payload []byte) *Message {
	return &Message{
		Type:      msgType,
		Payload:   payload,
		Timestamp: time.Now(),
	}
}

// Validation errors.
var (
	ErrEmptyPayload       = errors.New("payload cannot be empty for this message type")
	ErrZeroTimestamp      = errors.New("timestamp cannot be zero")
	ErrFutureTimestamp    = errors.New("timestamp cannot be in the future")
	ErrInvalidMessageType = errors.New("invalid message type")
)

// Validate checks that the message is well-formed.
func (m *Message) Validate() error {
	// Check timestamp
	if m.Timestamp.IsZero() {
		return ErrZeroTimestamp
	}
	if m.Timestamp.After(time.Now()) {
		return ErrFutureTimestamp
	}

	// Check message type
	if !m.Type.isValid() {
		return ErrInvalidMessageType
	}

	// Check payload requirements based on message type
	switch m.Type {
	case MsgAttestation, MsgVectorMatch, MsgUnmask:
		// These message types require a payload
		if len(m.Payload) == 0 {
			return ErrEmptyPayload
		}
	case MsgDealBreaker, MsgChat:
		// These can have empty payloads (though unusual)
	}

	return nil
}

// Sign adds a cryptographic signature to the message.
func (m *Message) Sign(signature []byte) {
	m.Signature = signature
}

// IsSigned returns true if the message has a signature attached.
func (m *Message) IsSigned() bool {
	return len(m.Signature) > 0
}

// Clone creates a deep copy of the message.
func (m *Message) Clone() *Message {
	clone := &Message{
		Type:      m.Type,
		Timestamp: m.Timestamp,
	}

	if m.Payload != nil {
		clone.Payload = make([]byte, len(m.Payload))
		copy(clone.Payload, m.Payload)
	}

	if m.Signature != nil {
		clone.Signature = make([]byte, len(m.Signature))
		copy(clone.Signature, m.Signature)
	}

	return clone
}

// Size returns an estimate of the serialized message size in bytes.
// This is useful for rate limiting and buffer allocation.
func (m *Message) Size() int {
	// Estimate: type (1 byte) + timestamp (8 bytes) + payload + signature
	const overhead = 1 + 8
	return overhead + len(m.Payload) + len(m.Signature)
}

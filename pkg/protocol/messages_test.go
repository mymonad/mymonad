package protocol

import (
	"bytes"
	"testing"
	"time"
)

func TestMessageTypeString(t *testing.T) {
	tests := []struct {
		msgType  MessageType
		expected string
	}{
		{MsgAttestation, "Attestation"},
		{MsgVectorMatch, "VectorMatch"},
		{MsgDealBreaker, "DealBreaker"},
		{MsgChat, "Chat"},
		{MsgUnmask, "Unmask"},
		{MessageType(99), "Unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.msgType.String(); got != tt.expected {
				t.Errorf("MessageType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNewMessage(t *testing.T) {
	payload := []byte("test payload")

	t.Run("creates message with correct fields", func(t *testing.T) {
		beforeTime := time.Now()
		msg := NewMessage(MsgAttestation, payload)
		afterTime := time.Now()

		if msg.Type != MsgAttestation {
			t.Errorf("expected type Attestation, got %v", msg.Type)
		}
		if !bytes.Equal(msg.Payload, payload) {
			t.Errorf("payload mismatch: expected %v, got %v", payload, msg.Payload)
		}
		if msg.Timestamp.Before(beforeTime) || msg.Timestamp.After(afterTime) {
			t.Errorf("timestamp %v not in expected range [%v, %v]",
				msg.Timestamp, beforeTime, afterTime)
		}
		if msg.Signature != nil {
			t.Error("signature should be nil for unsigned message")
		}
	})

	t.Run("creates message for each type", func(t *testing.T) {
		types := []MessageType{
			MsgAttestation,
			MsgVectorMatch,
			MsgDealBreaker,
			MsgChat,
			MsgUnmask,
		}

		for _, mt := range types {
			msg := NewMessage(mt, payload)
			if msg.Type != mt {
				t.Errorf("expected type %v, got %v", mt, msg.Type)
			}
		}
	})

	t.Run("handles nil payload", func(t *testing.T) {
		msg := NewMessage(MsgChat, nil)
		if msg.Payload != nil {
			t.Error("expected nil payload")
		}
	})

	t.Run("handles empty payload", func(t *testing.T) {
		msg := NewMessage(MsgChat, []byte{})
		if len(msg.Payload) != 0 {
			t.Error("expected empty payload")
		}
	})
}

func TestMessageValidate(t *testing.T) {
	t.Run("valid message passes validation", func(t *testing.T) {
		msg := NewMessage(MsgAttestation, []byte("payload"))
		if err := msg.Validate(); err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("empty payload for attestation is invalid", func(t *testing.T) {
		msg := NewMessage(MsgAttestation, nil)
		if err := msg.Validate(); err == nil {
			t.Error("expected error for empty attestation payload")
		}
	})

	t.Run("empty payload for vector match is invalid", func(t *testing.T) {
		msg := NewMessage(MsgVectorMatch, nil)
		if err := msg.Validate(); err == nil {
			t.Error("expected error for empty vector match payload")
		}
	})

	t.Run("empty payload for unmask is invalid", func(t *testing.T) {
		msg := NewMessage(MsgUnmask, nil)
		if err := msg.Validate(); err == nil {
			t.Error("expected error for empty unmask payload")
		}
	})

	t.Run("zero timestamp is invalid", func(t *testing.T) {
		msg := &Message{
			Type:      MsgChat,
			Payload:   []byte("test"),
			Timestamp: time.Time{},
		}
		if err := msg.Validate(); err == nil {
			t.Error("expected error for zero timestamp")
		}
	})

	t.Run("future timestamp is invalid", func(t *testing.T) {
		msg := &Message{
			Type:      MsgChat,
			Payload:   []byte("test"),
			Timestamp: time.Now().Add(time.Hour),
		}
		if err := msg.Validate(); err == nil {
			t.Error("expected error for future timestamp")
		}
	})

	t.Run("invalid message type is rejected", func(t *testing.T) {
		msg := &Message{
			Type:      MessageType(99),
			Payload:   []byte("test"),
			Timestamp: time.Now(),
		}
		if err := msg.Validate(); err == nil {
			t.Error("expected error for invalid message type")
		}
	})
}

func TestMessageSign(t *testing.T) {
	msg := NewMessage(MsgAttestation, []byte("test payload"))

	t.Run("sign adds signature", func(t *testing.T) {
		signature := []byte("mock-signature")
		msg.Sign(signature)

		if !bytes.Equal(msg.Signature, signature) {
			t.Errorf("signature mismatch: expected %v, got %v", signature, msg.Signature)
		}
	})

	t.Run("IsSigned returns true when signed", func(t *testing.T) {
		msg := NewMessage(MsgAttestation, []byte("test"))
		if msg.IsSigned() {
			t.Error("expected unsigned message")
		}

		msg.Sign([]byte("sig"))
		if !msg.IsSigned() {
			t.Error("expected signed message")
		}
	})
}

func TestMessageClone(t *testing.T) {
	original := NewMessage(MsgAttestation, []byte("test payload"))
	original.Sign([]byte("signature"))

	clone := original.Clone()

	t.Run("clone has same values", func(t *testing.T) {
		if clone.Type != original.Type {
			t.Errorf("type mismatch: %v vs %v", clone.Type, original.Type)
		}
		if !bytes.Equal(clone.Payload, original.Payload) {
			t.Error("payload mismatch")
		}
		if !clone.Timestamp.Equal(original.Timestamp) {
			t.Error("timestamp mismatch")
		}
		if !bytes.Equal(clone.Signature, original.Signature) {
			t.Error("signature mismatch")
		}
	})

	t.Run("clone is independent", func(t *testing.T) {
		clone.Payload[0] = 'X'
		if bytes.Equal(clone.Payload, original.Payload) {
			t.Error("modifying clone affected original payload")
		}

		clone.Signature[0] = 'Y'
		if bytes.Equal(clone.Signature, original.Signature) {
			t.Error("modifying clone affected original signature")
		}
	})
}

func TestMessageSize(t *testing.T) {
	t.Run("calculates correct size", func(t *testing.T) {
		payload := []byte("test payload")
		signature := []byte("signature")
		msg := NewMessage(MsgAttestation, payload)
		msg.Sign(signature)

		// Size should be: type (1 byte) + payload length + timestamp (8 bytes) + signature length
		// This is a simplified calculation; actual wire format may differ
		expectedMinSize := 1 + len(payload) + 8 + len(signature)
		actualSize := msg.Size()

		if actualSize < expectedMinSize {
			t.Errorf("size too small: expected at least %d, got %d", expectedMinSize, actualSize)
		}
	})

	t.Run("empty message has minimum size", func(t *testing.T) {
		msg := NewMessage(MsgChat, nil)
		if msg.Size() <= 0 {
			t.Error("message should have non-zero size")
		}
	})
}

package handshake

import (
	"bytes"
	"testing"

	pb "github.com/mymonad/mymonad/api/proto"
)

func TestCodec_WriteReadEnvelope(t *testing.T) {
	var buf bytes.Buffer

	// Write envelope
	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_REQUEST,
		Payload:   []byte("test payload"),
		Timestamp: 1234567890,
		Signature: []byte("sig"),
	}

	err := WriteEnvelope(&buf, env)
	if err != nil {
		t.Fatalf("write error: %v", err)
	}

	// Read envelope back
	readEnv, err := ReadEnvelope(&buf)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}

	if readEnv.Type != env.Type {
		t.Errorf("type mismatch: got %v, want %v", readEnv.Type, env.Type)
	}

	if !bytes.Equal(readEnv.Payload, env.Payload) {
		t.Error("payload mismatch")
	}

	if readEnv.Timestamp != env.Timestamp {
		t.Error("timestamp mismatch")
	}
}

func TestCodec_MaxMessageSize(t *testing.T) {
	var buf bytes.Buffer

	// Create oversized payload
	env := &pb.HandshakeEnvelope{
		Type:    pb.MessageType_ATTESTATION_REQUEST,
		Payload: make([]byte, MaxMessageSize+1),
	}

	err := WriteEnvelope(&buf, env)
	if err == nil {
		t.Error("expected error for oversized message")
	}
}

func TestCodec_ReadInvalidLength(t *testing.T) {
	// Create buffer with zero length prefix
	buf := bytes.NewBuffer([]byte{0, 0, 0, 0})

	_, err := ReadEnvelope(buf)
	if err != ErrInvalidLength {
		t.Errorf("expected ErrInvalidLength, got %v", err)
	}
}

func TestCodec_ReadOversizedLength(t *testing.T) {
	// Create buffer with length exceeding MaxMessageSize
	// MaxMessageSize is 1MB = 1048576 bytes
	// Encode as big-endian uint32: 0x00200001 = 2097153 > MaxMessageSize
	buf := bytes.NewBuffer([]byte{0x00, 0x20, 0x00, 0x01})

	_, err := ReadEnvelope(buf)
	if err != ErrMessageTooLarge {
		t.Errorf("expected ErrMessageTooLarge, got %v", err)
	}
}

func TestCodec_ReadTruncatedData(t *testing.T) {
	var buf bytes.Buffer

	// Write a valid envelope first
	env := &pb.HandshakeEnvelope{
		Type:    pb.MessageType_ATTESTATION_REQUEST,
		Payload: []byte("test payload"),
	}

	err := WriteEnvelope(&buf, env)
	if err != nil {
		t.Fatalf("write error: %v", err)
	}

	// Truncate the buffer (remove some data)
	data := buf.Bytes()
	truncatedBuf := bytes.NewBuffer(data[:len(data)-5])

	_, err = ReadEnvelope(truncatedBuf)
	if err == nil {
		t.Error("expected error for truncated data")
	}
}

func TestCodec_MultipleEnvelopes(t *testing.T) {
	var buf bytes.Buffer

	// Write multiple envelopes
	envelopes := []*pb.HandshakeEnvelope{
		{
			Type:      pb.MessageType_ATTESTATION_REQUEST,
			Payload:   []byte("first"),
			Timestamp: 100,
		},
		{
			Type:      pb.MessageType_ATTESTATION_RESPONSE,
			Payload:   []byte("second"),
			Timestamp: 200,
		},
		{
			Type:      pb.MessageType_VECTOR_MATCH_REQUEST,
			Payload:   []byte("third"),
			Timestamp: 300,
		},
	}

	for _, env := range envelopes {
		if err := WriteEnvelope(&buf, env); err != nil {
			t.Fatalf("write error: %v", err)
		}
	}

	// Read them back in order
	for i, expected := range envelopes {
		readEnv, err := ReadEnvelope(&buf)
		if err != nil {
			t.Fatalf("read error at index %d: %v", i, err)
		}

		if readEnv.Type != expected.Type {
			t.Errorf("envelope %d: type mismatch: got %v, want %v", i, readEnv.Type, expected.Type)
		}

		if !bytes.Equal(readEnv.Payload, expected.Payload) {
			t.Errorf("envelope %d: payload mismatch", i)
		}

		if readEnv.Timestamp != expected.Timestamp {
			t.Errorf("envelope %d: timestamp mismatch", i)
		}
	}
}

func TestCodec_EmptyPayload(t *testing.T) {
	var buf bytes.Buffer

	// Write envelope with empty payload
	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_REJECT,
		Timestamp: 999,
	}

	err := WriteEnvelope(&buf, env)
	if err != nil {
		t.Fatalf("write error: %v", err)
	}

	readEnv, err := ReadEnvelope(&buf)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}

	if readEnv.Type != env.Type {
		t.Errorf("type mismatch: got %v, want %v", readEnv.Type, env.Type)
	}

	if readEnv.Timestamp != env.Timestamp {
		t.Errorf("timestamp mismatch: got %v, want %v", readEnv.Timestamp, env.Timestamp)
	}
}

func TestCodec_SignaturePreserved(t *testing.T) {
	var buf bytes.Buffer

	signature := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_CHAT_MESSAGE,
		Payload:   []byte("encrypted content"),
		Timestamp: 1234567890,
		Signature: signature,
	}

	err := WriteEnvelope(&buf, env)
	if err != nil {
		t.Fatalf("write error: %v", err)
	}

	readEnv, err := ReadEnvelope(&buf)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}

	if !bytes.Equal(readEnv.Signature, signature) {
		t.Errorf("signature mismatch: got %v, want %v", readEnv.Signature, signature)
	}
}

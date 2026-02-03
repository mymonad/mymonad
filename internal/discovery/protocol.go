// Package discovery provides peer discovery mechanisms for the P2P network.
// This file implements the protocol stream handler for commit-reveal exchanges.
package discovery

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/libp2p/go-libp2p/core/peer"
	pb "github.com/mymonad/mymonad/api/proto"
	"google.golang.org/protobuf/proto"
)

// ProtocolID is the libp2p protocol identifier for discovery streams.
const ProtocolID = "/mymonad/discovery/1.0.0"

// MaxPayloadSize is the maximum allowed payload size (16 MB).
// This prevents memory exhaustion attacks from malicious peers.
const MaxPayloadSize = 16 * 1024 * 1024

// MessageType identifies the type of discovery message.
type MessageType uint8

const (
	// MessageTypeCommit indicates a DiscoveryCommit message.
	MessageTypeCommit MessageType = iota
	// MessageTypeReveal indicates a DiscoveryReveal message.
	MessageTypeReveal
	// MessageTypeReject indicates a DiscoveryReject message.
	MessageTypeReject
)

// ProtocolMessage wraps discovery protocol messages for stream I/O.
type ProtocolMessage struct {
	// Type identifies the message type.
	Type MessageType
	// Payload contains the serialized protobuf message.
	Payload []byte
}

// Protocol error types.
var (
	// ErrNilMessage is returned when attempting to write a nil message.
	ErrNilMessage = errors.New("message cannot be nil")
	// ErrPayloadTooLarge is returned when payload exceeds MaxPayloadSize.
	ErrPayloadTooLarge = errors.New("payload exceeds maximum size")
	// ErrUnexpectedMessageType is returned when message type doesn't match expected.
	ErrUnexpectedMessageType = errors.New("unexpected message type")
)

// WriteMessage writes a protocol message to a stream.
// Format: [type:1 byte][length:4 bytes BE][payload]
func WriteMessage(w io.Writer, msg *ProtocolMessage) error {
	if msg == nil {
		return ErrNilMessage
	}

	// Write message type (1 byte)
	if _, err := w.Write([]byte{byte(msg.Type)}); err != nil {
		return fmt.Errorf("write type: %w", err)
	}

	// Write payload length (4 bytes big-endian)
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(msg.Payload)))
	if _, err := w.Write(lenBuf); err != nil {
		return fmt.Errorf("write length: %w", err)
	}

	// Write payload
	if len(msg.Payload) > 0 {
		if _, err := w.Write(msg.Payload); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	}

	return nil
}

// ReadMessage reads a protocol message from a stream.
// Returns io.EOF if the stream is empty.
func ReadMessage(r io.Reader) (*ProtocolMessage, error) {
	// Read message type (1 byte)
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, typeBuf); err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("read type: %w", err)
	}

	// Read payload length (4 bytes big-endian)
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	payloadLen := binary.BigEndian.Uint32(lenBuf)

	// Validate payload size
	if payloadLen > MaxPayloadSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrPayloadTooLarge, payloadLen)
	}

	// Read payload
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("read payload: %w", err)
		}
	}

	return &ProtocolMessage{
		Type:    MessageType(typeBuf[0]),
		Payload: payload,
	}, nil
}

// WriteCommit sends a DiscoveryCommit message.
func WriteCommit(w io.Writer, commit *pb.DiscoveryCommit) error {
	if commit == nil {
		return ErrNilMessage
	}

	payload, err := proto.Marshal(commit)
	if err != nil {
		return fmt.Errorf("marshal commit: %w", err)
	}

	return WriteMessage(w, &ProtocolMessage{
		Type:    MessageTypeCommit,
		Payload: payload,
	})
}

// ReadCommit reads and parses a DiscoveryCommit message.
// Returns an error if the message type is not MessageTypeCommit.
func ReadCommit(r io.Reader) (*pb.DiscoveryCommit, error) {
	msg, err := ReadMessage(r)
	if err != nil {
		return nil, err
	}

	if msg.Type != MessageTypeCommit {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrUnexpectedMessageType, msg.Type, MessageTypeCommit)
	}

	commit := &pb.DiscoveryCommit{}
	if err := proto.Unmarshal(msg.Payload, commit); err != nil {
		return nil, fmt.Errorf("unmarshal commit: %w", err)
	}

	return commit, nil
}

// WriteReveal sends a DiscoveryReveal message.
func WriteReveal(w io.Writer, reveal *pb.DiscoveryReveal) error {
	if reveal == nil {
		return ErrNilMessage
	}

	payload, err := proto.Marshal(reveal)
	if err != nil {
		return fmt.Errorf("marshal reveal: %w", err)
	}

	return WriteMessage(w, &ProtocolMessage{
		Type:    MessageTypeReveal,
		Payload: payload,
	})
}

// ReadReveal reads and parses a DiscoveryReveal message.
// Returns an error if the message type is not MessageTypeReveal.
func ReadReveal(r io.Reader) (*pb.DiscoveryReveal, error) {
	msg, err := ReadMessage(r)
	if err != nil {
		return nil, err
	}

	if msg.Type != MessageTypeReveal {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrUnexpectedMessageType, msg.Type, MessageTypeReveal)
	}

	reveal := &pb.DiscoveryReveal{}
	if err := proto.Unmarshal(msg.Payload, reveal); err != nil {
		return nil, fmt.Errorf("unmarshal reveal: %w", err)
	}

	return reveal, nil
}

// WriteReject sends a DiscoveryReject message with the given reason.
func WriteReject(w io.Writer, reason string) error {
	reject := &pb.DiscoveryReject{
		Reason: reason,
	}

	payload, err := proto.Marshal(reject)
	if err != nil {
		return fmt.Errorf("marshal reject: %w", err)
	}

	return WriteMessage(w, &ProtocolMessage{
		Type:    MessageTypeReject,
		Payload: payload,
	})
}

// ReadReject reads and parses a DiscoveryReject message.
// Returns an error if the message type is not MessageTypeReject.
func ReadReject(r io.Reader) (*pb.DiscoveryReject, error) {
	msg, err := ReadMessage(r)
	if err != nil {
		return nil, err
	}

	if msg.Type != MessageTypeReject {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrUnexpectedMessageType, msg.Type, MessageTypeReject)
	}

	reject := &pb.DiscoveryReject{}
	if err := proto.Unmarshal(msg.Payload, reject); err != nil {
		return nil, fmt.Errorf("unmarshal reject: %w", err)
	}

	return reject, nil
}

// shouldInitiate determines if local peer should initiate (lower peer ID).
// In a commit-reveal protocol, one peer must send first to avoid deadlock.
// The peer with the lexicographically lower ID initiates.
// If IDs are equal, neither initiates (this should not happen in practice).
func shouldInitiate(localID, remoteID peer.ID) bool {
	return localID < remoteID
}

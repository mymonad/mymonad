// Package handshake provides wire codec for length-prefixed protobuf encoding.
package handshake

import (
	"encoding/binary"
	"errors"
	"io"

	pb "github.com/mymonad/mymonad/api/proto"
	"google.golang.org/protobuf/proto"
)

const (
	// MaxMessageSize is the maximum allowed message size (1MB).
	MaxMessageSize = 1 << 20

	// LengthPrefixSize is the size of the length prefix (4 bytes).
	LengthPrefixSize = 4
)

var (
	// ErrMessageTooLarge is returned when a message exceeds MaxMessageSize.
	ErrMessageTooLarge = errors.New("handshake: message exceeds maximum size")

	// ErrInvalidLength is returned when the message length is invalid (e.g., zero).
	ErrInvalidLength = errors.New("handshake: invalid message length")
)

// WriteEnvelope writes a length-prefixed protobuf envelope to the writer.
// Format: [4-byte big-endian length][protobuf data]
func WriteEnvelope(w io.Writer, env *pb.HandshakeEnvelope) error {
	data, err := proto.Marshal(env)
	if err != nil {
		return err
	}

	if len(data) > MaxMessageSize {
		return ErrMessageTooLarge
	}

	// Write length prefix (big-endian uint32)
	lengthBuf := make([]byte, LengthPrefixSize)
	binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))

	if _, err := w.Write(lengthBuf); err != nil {
		return err
	}

	if _, err := w.Write(data); err != nil {
		return err
	}

	return nil
}

// ReadEnvelope reads a length-prefixed protobuf envelope from the reader.
// Format: [4-byte big-endian length][protobuf data]
func ReadEnvelope(r io.Reader) (*pb.HandshakeEnvelope, error) {
	// Read length prefix
	lengthBuf := make([]byte, LengthPrefixSize)
	if _, err := io.ReadFull(r, lengthBuf); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(lengthBuf)

	if length > MaxMessageSize {
		return nil, ErrMessageTooLarge
	}

	if length == 0 {
		return nil, ErrInvalidLength
	}

	// Read message data
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}

	// Unmarshal protobuf
	env := &pb.HandshakeEnvelope{}
	if err := proto.Unmarshal(data, env); err != nil {
		return nil, err
	}

	return env, nil
}

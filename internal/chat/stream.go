// Package chat provides encrypted chat functionality for the MyMonad protocol.
// This file implements stream handling for the chat protocol including
// length-prefixed reading/writing and the main read loop.
package chat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"

	pb "github.com/mymonad/mymonad/api/proto"
	"google.golang.org/protobuf/proto"
)

// Stream-related constants.
const (
	// MaxEnvelopeSize is the maximum size of a serialized ChatEnvelope in bytes.
	// This is set to 8KB to accommodate 4KB message + protobuf overhead + encryption overhead.
	MaxEnvelopeSize = 8192

	// lengthPrefixSize is the size of the length prefix in bytes (4 bytes, big-endian).
	lengthPrefixSize = 4
)

// Stream-related errors.
var (
	// ErrSessionClosed is returned when attempting operations on a closed session.
	ErrSessionClosed = errors.New("chat: session closed")

	// ErrStreamBroken is returned when the stream is nil or has failed.
	ErrStreamBroken = errors.New("chat: stream broken")

	// ErrEnvelopeTooLarge is returned when an envelope exceeds MaxEnvelopeSize.
	ErrEnvelopeTooLarge = errors.New("chat: envelope too large")
)

// StreamRW defines the interface for stream read/write operations.
// This abstraction allows testing without actual network streams.
type StreamRW interface {
	io.Reader
	io.Writer
}

// writeEnvelopeImpl writes a length-prefixed ChatEnvelope to the stream.
// Format: [4 bytes big-endian length][protobuf data]
//
// This method checks if the session is closed and if the stream is valid
// before attempting to write.
func (s *ChatSession) writeEnvelopeImpl(env *pb.ChatEnvelope) error {
	// Check session state
	s.mu.RLock()
	if !s.isOpen {
		s.mu.RUnlock()
		return ErrSessionClosed
	}
	streamRW := s.streamRW
	s.mu.RUnlock()

	// Check stream validity
	if streamRW == nil {
		return ErrStreamBroken
	}

	// Marshal the envelope
	payload, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	// Write length prefix (4 bytes big-endian)
	lengthBuf := make([]byte, lengthPrefixSize)
	binary.BigEndian.PutUint32(lengthBuf, uint32(len(payload)))

	// Write length prefix
	if _, err := streamRW.Write(lengthBuf); err != nil {
		return fmt.Errorf("write length prefix: %w", err)
	}

	// Write payload
	if _, err := streamRW.Write(payload); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}

	return nil
}

// readEnvelopeImpl reads a length-prefixed ChatEnvelope from the stream.
// Format: [4 bytes big-endian length][protobuf data]
//
// This method validates that the envelope size does not exceed MaxEnvelopeSize.
func (s *ChatSession) readEnvelopeImpl() (*pb.ChatEnvelope, error) {
	// Get stream reference
	s.mu.RLock()
	streamRW := s.streamRW
	s.mu.RUnlock()

	// Check stream validity
	if streamRW == nil {
		return nil, ErrStreamBroken
	}

	// Read length prefix
	lengthBuf := make([]byte, lengthPrefixSize)
	if _, err := io.ReadFull(streamRW, lengthBuf); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("read length prefix: %w", err)
	}

	// Parse length
	length := binary.BigEndian.Uint32(lengthBuf)

	// Validate size
	if length > MaxEnvelopeSize {
		return nil, fmt.Errorf("%w: size %d exceeds max %d", ErrEnvelopeTooLarge, length, MaxEnvelopeSize)
	}

	// Read payload
	payload := make([]byte, length)
	if _, err := io.ReadFull(streamRW, payload); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("read payload: %w", err)
	}

	// Unmarshal envelope
	var env pb.ChatEnvelope
	if err := proto.Unmarshal(payload, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}

	return &env, nil
}

// readLoop is the main read loop for incoming envelopes.
// It reads envelopes in a loop and dispatches to the appropriate handler
// based on the payload type (message, ack, or typing).
//
// This method calls handleStreamClose() on error or EOF.
// It should be called as a goroutine when a chat is opened.
func (s *ChatSession) readLoop() {
	slog.Debug("chat readLoop started",
		"session_id", fmt.Sprintf("%x", s.sessionID),
	)

	for {
		// Check if session is still open
		s.mu.RLock()
		isOpen := s.isOpen
		s.mu.RUnlock()

		if !isOpen {
			slog.Debug("chat readLoop exiting: session closed")
			return
		}

		// Read next envelope
		env, err := s.readEnvelopeImpl()
		if err != nil {
			if errors.Is(err, io.EOF) {
				slog.Debug("chat readLoop: stream closed (EOF)")
			} else {
				slog.Warn("chat readLoop: read error", "error", err)
			}
			s.handleStreamClose()
			return
		}

		// Dispatch based on payload type
		switch payload := env.GetPayload().(type) {
		case *pb.ChatEnvelope_Message:
			s.handleMessage(payload.Message)

		case *pb.ChatEnvelope_Ack:
			s.handleAck(payload.Ack)

		case *pb.ChatEnvelope_Typing:
			s.handleTyping(payload.Typing)

		default:
			slog.Warn("chat readLoop: unknown envelope payload type")
		}
	}
}

// handleStreamClose handles stream closure.
// It logs the stream closure and calls Cleanup() if the session was open.
func (s *ChatSession) handleStreamClose() {
	slog.Debug("chat stream closed",
		"session_id", fmt.Sprintf("%x", s.sessionID),
	)

	// Cleanup will handle idempotency (checking isOpen)
	s.Cleanup()
}

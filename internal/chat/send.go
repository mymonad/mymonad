// Package chat provides encrypted chat functionality for the MyMonad protocol.
// This file implements message sending with encryption and pending ACK tracking.
package chat

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
	"google.golang.org/protobuf/proto"
)

// SendMessage encrypts and sends a text message to the peer.
// It generates a unique message ID, encrypts the message using the session's
// chat key, stores it in the message buffer, and tracks it for ACK confirmation.
//
// Parameters:
//   - text: The message text to send (max MaxMessageSize bytes)
//
// Returns the message ID (16 bytes UUID) or an error.
func (s *ChatSession) SendMessage(text string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return nil, fmt.Errorf("chat session closed")
	}

	if len(text) > MaxMessageSize {
		return nil, fmt.Errorf("message exceeds max size: %d > %d", len(text), MaxMessageSize)
	}

	// Generate message ID (16 bytes UUID)
	messageID := make([]byte, 16)
	if _, err := rand.Read(messageID); err != nil {
		return nil, fmt.Errorf("generate message id: %w", err)
	}

	// Serialize plaintext to protobuf
	plaintext := &pb.ChatPlaintext{
		Text:   text,
		SentAt: time.Now().UnixMilli(),
	}
	plaintextBytes, err := proto.Marshal(plaintext)
	if err != nil {
		return nil, fmt.Errorf("marshal plaintext: %w", err)
	}

	// Encrypt using chat key
	ciphertext, err := Encrypt(s.chatKey, plaintextBytes)
	if err != nil {
		zeroFill(plaintextBytes)
		return nil, fmt.Errorf("encrypt: %w", err)
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

	if err := s.writeEnvelope(envelope); err != nil {
		zeroFill(plaintextBytes)
		return nil, fmt.Errorf("send message: %w", err)
	}

	// Store in buffer
	stored := &StoredMessage{
		ID:        messageID,
		Plaintext: plaintextBytes, // Ownership transferred
		SentAt:    time.Now(),
		Direction: DirectionSent,
	}
	s.storeMessageLocked(stored)

	// Track pending ACK with a separate copy of plaintext
	// (StoredMessage owns the original; eviction would corrupt shared reference)
	pendingPlaintext := make([]byte, len(plaintextBytes))
	copy(pendingPlaintext, plaintextBytes)
	s.pendingAcks[hex.EncodeToString(messageID)] = &PendingMessage{
		ID:        messageID,
		Plaintext: pendingPlaintext,
		SentAt:    time.Now(),
		Retries:   0,
	}

	s.lastActivity = time.Now()
	return messageID, nil
}

// storeMessageLocked adds a message to the RAM buffer with size limit.
// Must be called while holding the session lock.
// If the buffer exceeds MaxBufferedMessages, the oldest message is evicted
// and its plaintext is securely wiped.
func (s *ChatSession) storeMessageLocked(msg *StoredMessage) {
	// Evict and wipe oldest if over limit
	if len(s.messages) >= MaxBufferedMessages {
		evicted := s.messages[0]
		zeroFill(evicted.Plaintext)
		s.messages = s.messages[1:]
	}

	s.messages = append(s.messages, msg)
}

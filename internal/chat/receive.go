// Package chat provides encrypted chat functionality for the MyMonad protocol.
// This file implements message receiving with decryption and ACK handling.
package chat

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
	"google.golang.org/protobuf/proto"
)

// handleMessage processes an incoming encrypted ChatMessage.
// It decrypts the message, stores it in the session buffer, and sends an ACK.
// On decryption or parsing failure, the message is silently dropped (logged).
func (s *ChatSession) handleMessage(msg *pb.ChatMessage) {
	// Reassemble ciphertext: nonce || encrypted_payload
	ciphertext := append(msg.Nonce, msg.Ciphertext...)

	// Decrypt using the session's chat key
	s.mu.RLock()
	chatKey := s.chatKey
	s.mu.RUnlock()

	plaintext, err := Decrypt(chatKey, ciphertext)
	if err != nil {
		slog.Warn("failed to decrypt message", "error", err)
		return
	}

	// Parse plaintext to ChatPlaintext
	var content pb.ChatPlaintext
	if err := proto.Unmarshal(plaintext, &content); err != nil {
		slog.Warn("failed to parse plaintext", "error", err)
		zeroFill(plaintext)
		return
	}

	// Send ACK immediately after successful decryption
	ack := &pb.ChatEnvelope{
		Payload: &pb.ChatEnvelope_Ack{
			Ack: &pb.ChatAck{
				MessageId:   msg.MessageId,
				MessageHash: sha256Sum(plaintext),
			},
		},
	}
	if err := s.writeEnvelope(ack); err != nil {
		slog.Warn("failed to send ack", "error", err)
		// Continue to store message even if ACK fails
	}

	// Store received message
	s.mu.Lock()
	s.storeMessageLocked(&StoredMessage{
		ID:        msg.MessageId,
		Plaintext: plaintext, // Ownership transferred
		SentAt:    time.UnixMilli(content.SentAt),
		Direction: DirectionReceived,
	})
	s.lastActivity = time.Now()
	s.mu.Unlock()

	// Notify callback with a copy of plaintext
	// The original plaintext is owned by StoredMessage and will be zeroed on cleanup
	if s.onMessage != nil {
		// Make a copy for the callback to prevent callers from holding references
		// to sensitive data that may be zeroed later
		callbackPlaintext := make([]byte, len(plaintext))
		copy(callbackPlaintext, plaintext)

		s.onMessage(&ReceivedMessage{
			ID:         msg.MessageId,
			Plaintext:  callbackPlaintext,
			ReceivedAt: time.Now(),
		})

		// Zero the callback copy after use - callers should not retain references
		zeroFill(callbackPlaintext)
	}
}

// handleAck processes an incoming ChatAck for a sent message.
// It verifies the hash matches our plaintext to confirm proper receipt.
// On hash mismatch, the ACK is rejected and the message remains pending.
func (s *ChatSession) handleAck(ack *pb.ChatAck) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idHex := hex.EncodeToString(ack.MessageId)
	pending, ok := s.pendingAcks[idHex]
	if !ok {
		return // Unknown or already ACKed
	}

	// Verify hash matches our plaintext
	expectedHash := sha256Sum(pending.Plaintext)
	if !bytes.Equal(ack.MessageHash, expectedHash) {
		slog.Warn("ack hash mismatch", "message_id", idHex)
		return
	}

	// Mark delivered
	delete(s.pendingAcks, idHex)
	now := time.Now()
	for _, msg := range s.messages {
		if bytes.Equal(msg.ID, ack.MessageId) {
			msg.DeliveredAt = &now
			break
		}
	}

	s.lastActivity = time.Now()

	// Notify callback
	if s.onDelivered != nil {
		s.onDelivered(ack.MessageId)
	}
}

// sha256Sum computes SHA-256 hash of the data.
func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

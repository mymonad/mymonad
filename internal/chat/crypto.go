// Package chat provides encrypted chat functionality for the MyMonad protocol.
package chat

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Cryptographic constants for chat encryption.
const (
	// ChatKeyInfo is the info string used for HKDF key derivation.
	// This provides domain separation for the derived key.
	ChatKeyInfo = "mymonad-chat-v1"

	// ChatKeyLength is the length of the derived chat key in bytes (AES-256).
	ChatKeyLength = 32

	// NonceLength is the length of the GCM nonce in bytes.
	NonceLength = 12

	// MaxMessageSize is the maximum allowed plaintext message size in bytes.
	MaxMessageSize = 4096

	// gcmTagSize is the size of the GCM authentication tag.
	gcmTagSize = 16
)

// Errors for crypto operations.
var (
	// ErrInvalidSharedSecret is returned when the shared secret is nil or empty.
	ErrInvalidSharedSecret = errors.New("chat: shared secret must not be nil or empty")

	// ErrInvalidSessionID is returned when the session ID is nil or empty.
	ErrInvalidSessionID = errors.New("chat: session ID must not be nil or empty")

	// ErrInvalidKey is returned when the encryption key is invalid.
	ErrInvalidKey = errors.New("chat: key must be exactly 32 bytes")

	// ErrMessageTooLarge is returned when the message exceeds MaxMessageSize.
	ErrMessageTooLarge = errors.New("chat: message exceeds maximum size")

	// ErrCiphertextTooShort is returned when the ciphertext is too short to be valid.
	ErrCiphertextTooShort = errors.New("chat: ciphertext too short")

	// ErrDecryptionFailed is returned when decryption fails (tampering or wrong key).
	ErrDecryptionFailed = errors.New("chat: decryption failed")
)

// DeriveKey derives a chat-specific key from the handshake shared secret.
// It uses HKDF with SHA-256 for key derivation.
//
// Parameters:
//   - sharedSecret: The X25519 shared secret from the handshake (must not be nil/empty)
//   - sessionID: Unique session identifier that binds the key to this session (must not be nil/empty)
//
// Returns a 32-byte key suitable for AES-256-GCM encryption.
func DeriveKey(sharedSecret []byte, sessionID []byte) ([]byte, error) {
	if len(sharedSecret) == 0 {
		return nil, ErrInvalidSharedSecret
	}
	if len(sessionID) == 0 {
		return nil, ErrInvalidSessionID
	}

	// Use HKDF to derive a key
	// - sharedSecret is the input key material
	// - sessionID is the salt (binds key to session)
	// - ChatKeyInfo provides domain separation
	hkdfReader := hkdf.New(sha256.New, sharedSecret, sessionID, []byte(ChatKeyInfo))

	key := make([]byte, ChatKeyLength)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("derive chat key: %w", err)
	}

	return key, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce.
// The ciphertext format is: nonce (12 bytes) || ciphertext || auth tag (16 bytes).
//
// Parameters:
//   - key: 32-byte encryption key
//   - plaintext: Message to encrypt (max MaxMessageSize bytes)
//
// Returns the ciphertext including nonce and authentication tag.
func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) != ChatKeyLength {
		return nil, ErrInvalidKey
	}
	if len(plaintext) > MaxMessageSize {
		return nil, ErrMessageTooLarge
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, NonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Encrypt: the nonce is prepended to the ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM.
// It expects the ciphertext format: nonce (12 bytes) || ciphertext || auth tag (16 bytes).
//
// Parameters:
//   - key: 32-byte encryption key
//   - ciphertext: The encrypted data including nonce and auth tag
//
// Returns the decrypted plaintext or an error if decryption fails.
func Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != ChatKeyLength {
		return nil, ErrInvalidKey
	}

	// Minimum length: nonce + auth tag
	minLen := NonceLength + gcmTagSize
	if len(ciphertext) < minLen {
		return nil, ErrCiphertextTooShort
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	// Extract nonce and encrypted data
	nonce := ciphertext[:NonceLength]
	encryptedData := ciphertext[NonceLength:]

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

// serializedIdentity is the JSON structure for storage.
type serializedIdentity struct {
	SigningKey        []byte `json:"signing_key"`
	VerifyKey         []byte `json:"verify_key"`
	EncryptionPrivate []byte `json:"encryption_private"`
	EncryptionPublic  []byte `json:"encryption_public"`
	DID               string `json:"did"`
}

// deriveKey uses Argon2id to derive an AES-256 key from passphrase.
func deriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
}

// SaveIdentity encrypts and saves identity to file.
func SaveIdentity(id *Identity, path, passphrase string) error {
	// Create parent directories if they don't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Serialize identity
	data, err := json.Marshal(serializedIdentity{
		SigningKey:        id.SigningKey,
		VerifyKey:         id.VerifyKey,
		EncryptionPrivate: id.EncryptionPrivate,
		EncryptionPublic:  id.EncryptionPublic,
		DID:               id.DID,
	})
	if err != nil {
		return fmt.Errorf("failed to serialize identity: %w", err)
	}

	// Generate salt
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key
	key := deriveKey(passphrase, salt)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Write: salt + nonce + ciphertext
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(salt); err != nil {
		return err
	}
	if _, err := f.Write(nonce); err != nil {
		return err
	}
	if _, err := f.Write(ciphertext); err != nil {
		return err
	}

	return nil
}

// LoadIdentity decrypts and loads identity from file.
func LoadIdentity(path, passphrase string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	if len(data) < 28 { // 16 salt + 12 nonce minimum
		return nil, fmt.Errorf("file too short")
	}

	salt := data[:16]
	key := deriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	nonce := data[16 : 16+nonceSize]
	ciphertext := data[16+nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong passphrase?): %w", err)
	}

	var stored serializedIdentity
	if err := json.Unmarshal(plaintext, &stored); err != nil {
		return nil, fmt.Errorf("failed to deserialize identity: %w", err)
	}

	return &Identity{
		SigningKey:        stored.SigningKey,
		VerifyKey:         stored.VerifyKey,
		EncryptionPrivate: stored.EncryptionPrivate,
		EncryptionPublic:  stored.EncryptionPublic,
		DID:               stored.DID,
	}, nil
}

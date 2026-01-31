// Package monad provides encrypted persistence for the Monad affinity vector.
// The Monad is serialized to a binary format and encrypted with AES-256-GCM
// before being written to disk, ensuring privacy of user data at rest.
package monad

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"
)

// ErrInvalidKeyLength is returned when the encryption key is not 32 bytes.
var ErrInvalidKeyLength = fmt.Errorf("key must be 32 bytes for AES-256")

// ErrUnsupportedFormatVersion is returned when loading a file with an unknown format version.
var ErrUnsupportedFormatVersion = fmt.Errorf("unsupported format version")

// formatVersion is the current binary format version.
// Version 1: formatVersion(1) + version(8) + doccount(8) + updated(8) + dims(4) + vector(dims*4)
const formatVersion byte = 1

// Save encrypts and saves the Monad to disk using atomic write.
// Key must be 32 bytes (AES-256).
// File format: nonce(12) + ciphertext
// Binary serialization: formatVersion(1) + version(8) + doccount(8) + updated(8) + dims(4) + vector(dims*4)
//
// Atomic write ensures data integrity:
// 1. Write to a temp file in the same directory
// 2. Sync the temp file to ensure data is flushed to disk
// 3. Rename temp file to target path (atomic on POSIX)
func Save(m *Monad, path string, key []byte) error {
	if len(key) != 32 {
		return ErrInvalidKeyLength
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Serialize: formatVersion(1) + version(8) + doccount(8) + updated(8) + dims(4) + vector(dims*4)
	dims := len(m.Vector)
	dataLen := 1 + 8 + 8 + 8 + 4 + dims*4
	data := make([]byte, dataLen)

	data[0] = formatVersion
	binary.LittleEndian.PutUint64(data[1:9], uint64(m.Version))
	binary.LittleEndian.PutUint64(data[9:17], uint64(m.DocCount))
	binary.LittleEndian.PutUint64(data[17:25], uint64(m.UpdatedAt.Unix()))
	binary.LittleEndian.PutUint32(data[25:29], uint32(dims))

	offset := 29
	for _, v := range m.Vector {
		binary.LittleEndian.PutUint32(data[offset:offset+4], math.Float32bits(v))
		offset += 4
	}

	// Encrypt with AES-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Create parent directories if they don't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Atomic write: write to temp file, sync, then rename
	// Temp file in same directory ensures rename is atomic on POSIX
	tmpPath := path + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	// Write nonce + ciphertext
	if _, err := f.Write(nonce); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write nonce: %w", err)
	}
	if _, err := f.Write(ciphertext); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write ciphertext: %w", err)
	}

	// Sync to ensure data is flushed to disk before rename
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to sync file: %w", err)
	}

	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Atomic rename (on POSIX, rename is atomic when source and dest are on same filesystem)
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// Load decrypts and loads a Monad from disk.
// Key must be 32 bytes (AES-256).
func Load(path string, key []byte) (*Monad, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeyLength
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("file too short: expected at least %d bytes for nonce", nonceSize)
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Minimum size: formatVersion(1) + version(8) + doccount(8) + updated(8) + dims(4) = 29 bytes
	if len(plaintext) < 29 {
		return nil, fmt.Errorf("data too short: expected at least 29 bytes, got %d", len(plaintext))
	}

	// Check format version
	fileFormatVersion := plaintext[0]
	if fileFormatVersion != formatVersion {
		return nil, fmt.Errorf("%w: got %d, expected %d", ErrUnsupportedFormatVersion, fileFormatVersion, formatVersion)
	}

	version := int64(binary.LittleEndian.Uint64(plaintext[1:9]))
	docCount := int64(binary.LittleEndian.Uint64(plaintext[9:17]))
	updatedUnix := int64(binary.LittleEndian.Uint64(plaintext[17:25]))
	dims := int(binary.LittleEndian.Uint32(plaintext[25:29]))

	expectedLen := 29 + dims*4
	if len(plaintext) < expectedLen {
		return nil, fmt.Errorf("data length mismatch: expected %d bytes, got %d", expectedLen, len(plaintext))
	}

	vector := make([]float32, dims)
	offset := 29
	for i := range vector {
		bits := binary.LittleEndian.Uint32(plaintext[offset : offset+4])
		vector[i] = math.Float32frombits(bits)
		offset += 4
	}

	return &Monad{
		Vector:    vector,
		Version:   version,
		DocCount:  docCount,
		UpdatedAt: time.Unix(updatedUnix, 0),
	}, nil
}

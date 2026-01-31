package monad

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMonadSaveLoad(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "monad.enc")
	key := make([]byte, 32) // Zero key for testing

	original := New(3)
	original.Vector = []float32{0.1, 0.2, 0.3}
	original.Version = 5
	original.DocCount = 100

	err := Save(original, path, key)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("File should exist")
	}

	loaded, err := Load(path, key)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Version != original.Version {
		t.Errorf("Version mismatch: got %d, want %d", loaded.Version, original.Version)
	}
	if loaded.DocCount != original.DocCount {
		t.Errorf("DocCount mismatch: got %d, want %d", loaded.DocCount, original.DocCount)
	}
	for i := range original.Vector {
		if loaded.Vector[i] != original.Vector[i] {
			t.Errorf("Vector[%d] mismatch: got %f, want %f", i, loaded.Vector[i], original.Vector[i])
		}
	}
}

func TestMonadLoadWrongKey(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "monad.enc")
	correctKey := []byte("correct-key-32-bytes-long-xxxxx")
	wrongKey := []byte("wrong-key-32-bytes-long-xxxxxxx")

	m := New(3)
	m.Vector = []float32{0.1, 0.2, 0.3}
	Save(m, path, correctKey)

	_, err := Load(path, wrongKey)
	if err == nil {
		t.Error("Load should fail with wrong key")
	}
}

func TestMonadSaveInvalidKeyLength(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "monad.enc")

	m := New(3)
	m.Vector = []float32{0.1, 0.2, 0.3}

	// Key too short (16 bytes instead of 32)
	shortKey := make([]byte, 16)
	err := Save(m, path, shortKey)
	if err == nil {
		t.Error("Save should fail with invalid key length")
	}

	// Key too long (64 bytes instead of 32)
	longKey := make([]byte, 64)
	err = Save(m, path, longKey)
	if err == nil {
		t.Error("Save should fail with invalid key length")
	}
}

func TestMonadLoadInvalidKeyLength(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "monad.enc")
	validKey := make([]byte, 32)

	m := New(3)
	m.Vector = []float32{0.1, 0.2, 0.3}
	Save(m, path, validKey)

	// Try to load with invalid key length
	shortKey := make([]byte, 16)
	_, err := Load(path, shortKey)
	if err == nil {
		t.Error("Load should fail with invalid key length")
	}
}

func TestMonadLoadFileNotFound(t *testing.T) {
	key := make([]byte, 32)
	_, err := Load("/nonexistent/path/monad.enc", key)
	if err == nil {
		t.Error("Load should fail when file not found")
	}
}

func TestMonadLoadCorruptedFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "monad.enc")
	key := make([]byte, 32)

	// Write garbage data
	if err := os.WriteFile(path, []byte("corrupted data"), 0600); err != nil {
		t.Fatalf("Failed to write corrupted file: %v", err)
	}

	_, err := Load(path, key)
	if err == nil {
		t.Error("Load should fail with corrupted file")
	}
}

func TestMonadLoadTruncatedFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "monad.enc")
	key := make([]byte, 32)

	// Write file that's too short (less than nonce size)
	if err := os.WriteFile(path, []byte("short"), 0600); err != nil {
		t.Fatalf("Failed to write truncated file: %v", err)
	}

	_, err := Load(path, key)
	if err == nil {
		t.Error("Load should fail with truncated file")
	}
}

func TestMonadSaveCreatesParentDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "subdir", "nested", "monad.enc")
	key := make([]byte, 32)

	m := New(3)
	m.Vector = []float32{0.1, 0.2, 0.3}

	err := Save(m, path, key)
	if err != nil {
		t.Fatalf("Save should create parent directories: %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("File should exist")
	}
}

func TestMonadSaveFilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "monad.enc")
	key := make([]byte, 32)

	m := New(3)
	m.Vector = []float32{0.1, 0.2, 0.3}

	err := Save(m, path, key)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Failed to stat file: %v", err)
	}

	// Check that file permissions are restrictive (0600)
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("File permissions should be 0600, got %o", perm)
	}
}

func TestMonadSaveLoadPreservesUpdatedAt(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "monad.enc")
	key := make([]byte, 32)

	original := New(3)
	original.Vector = []float32{0.1, 0.2, 0.3}
	// UpdatedAt is set by New(), so we just verify it round-trips

	err := Save(original, path, key)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := Load(path, key)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Unix timestamps should match (we serialize to Unix seconds)
	if loaded.UpdatedAt.Unix() != original.UpdatedAt.Unix() {
		t.Errorf("UpdatedAt mismatch: got %v, want %v", loaded.UpdatedAt.Unix(), original.UpdatedAt.Unix())
	}
}

func TestMonadSaveLoadLargeVector(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "monad.enc")
	key := make([]byte, 32)

	// Use realistic embedding dimension (384 for sentence-transformers)
	dims := 384
	original := New(dims)
	for i := range original.Vector {
		original.Vector[i] = float32(i) / float32(dims)
	}
	original.Version = 12345
	original.DocCount = 999

	err := Save(original, path, key)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := Load(path, key)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(loaded.Vector) != dims {
		t.Errorf("Vector length mismatch: got %d, want %d", len(loaded.Vector), dims)
	}
	if loaded.Version != original.Version {
		t.Errorf("Version mismatch: got %d, want %d", loaded.Version, original.Version)
	}
	if loaded.DocCount != original.DocCount {
		t.Errorf("DocCount mismatch: got %d, want %d", loaded.DocCount, original.DocCount)
	}

	for i := range original.Vector {
		if loaded.Vector[i] != original.Vector[i] {
			t.Errorf("Vector[%d] mismatch: got %f, want %f", i, loaded.Vector[i], original.Vector[i])
		}
	}
}

func TestMonadSaveLoadEmptyVector(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "monad.enc")
	key := make([]byte, 32)

	original := New(0) // Empty vector
	original.Version = 1
	original.DocCount = 0

	err := Save(original, path, key)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := Load(path, key)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(loaded.Vector) != 0 {
		t.Errorf("Vector length should be 0, got %d", len(loaded.Vector))
	}
}

func TestMonadAtomicWritePreservesOriginal(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "monad.enc")
	key := make([]byte, 32)

	// Create and save original monad
	original := New(3)
	original.Vector = []float32{0.1, 0.2, 0.3}
	original.Version = 1
	original.DocCount = 10

	err := Save(original, path, key)
	if err != nil {
		t.Fatalf("Save original failed: %v", err)
	}

	// Save a new monad to the same path
	updated := New(3)
	updated.Vector = []float32{0.4, 0.5, 0.6}
	updated.Version = 2
	updated.DocCount = 20

	err = Save(updated, path, key)
	if err != nil {
		t.Fatalf("Save updated failed: %v", err)
	}

	// Verify temp file is cleaned up
	tmpPath := path + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("Temp file should not exist after successful save")
	}

	// Verify updated data was written
	loaded, err := Load(path, key)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Version != 2 {
		t.Errorf("Version mismatch: got %d, want 2", loaded.Version)
	}
	if loaded.DocCount != 20 {
		t.Errorf("DocCount mismatch: got %d, want 20", loaded.DocCount)
	}
}

func TestMonadAtomicWriteNoTempFileOnSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "monad.enc")
	key := make([]byte, 32)

	m := New(3)
	m.Vector = []float32{0.1, 0.2, 0.3}

	err := Save(m, path, key)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify temp file does not exist after successful write
	tmpPath := path + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("Temp file should be cleaned up after successful save")
	}

	// Verify target file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("Target file should exist after save")
	}
}

func TestMonadLoadUnsupportedFormatVersion(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "monad.enc")
	key := make([]byte, 32)

	// Create a file with format version 99 (unsupported)
	dims := 3
	dataLen := 1 + 8 + 8 + 8 + 4 + dims*4
	data := make([]byte, dataLen)

	data[0] = 99 // Unsupported format version
	binary.LittleEndian.PutUint64(data[1:9], 1)
	binary.LittleEndian.PutUint64(data[9:17], 10)
	binary.LittleEndian.PutUint64(data[17:25], uint64(time.Now().Unix()))
	binary.LittleEndian.PutUint32(data[25:29], uint32(dims))

	offset := 29
	for i := 0; i < dims; i++ {
		binary.LittleEndian.PutUint32(data[offset:offset+4], math.Float32bits(float32(i)*0.1))
		offset += 4
	}

	// Encrypt the data
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("Failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Write to file
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	f.Write(nonce)
	f.Write(ciphertext)
	f.Close()

	// Try to load - should fail with unsupported format version
	_, err = Load(path, key)
	if err == nil {
		t.Error("Load should fail with unsupported format version")
	}
	if err != nil && !contains(err.Error(), "unsupported format version") {
		t.Errorf("Error should mention unsupported format version, got: %v", err)
	}
}

func TestMonadFormatVersionInFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "monad.enc")
	key := make([]byte, 32)

	m := New(3)
	m.Vector = []float32{0.1, 0.2, 0.3}
	m.Version = 5
	m.DocCount = 100

	err := Save(m, path, key)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Read the raw file and decrypt to verify format version
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("Failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// First byte should be format version 1
	if plaintext[0] != 1 {
		t.Errorf("Format version should be 1, got %d", plaintext[0])
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

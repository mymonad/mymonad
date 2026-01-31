package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoadIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "keypair.enc")
	passphrase := "test-passphrase-123"

	// Generate identity
	original, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	// Save encrypted
	err = SaveIdentity(original, keyPath, passphrase)
	if err != nil {
		t.Fatalf("SaveIdentity failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("Key file should exist")
	}

	// Load and decrypt
	loaded, err := LoadIdentity(keyPath, passphrase)
	if err != nil {
		t.Fatalf("LoadIdentity failed: %v", err)
	}

	// Verify loaded matches original
	if loaded.DID != original.DID {
		t.Errorf("DID mismatch: got %s, want %s", loaded.DID, original.DID)
	}
	if string(loaded.EncryptionPublic) != string(original.EncryptionPublic) {
		t.Error("EncryptionPublic mismatch")
	}
}

func TestLoadIdentityWrongPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "keypair.enc")

	identity, _ := GenerateIdentity()
	SaveIdentity(identity, keyPath, "correct-passphrase")

	_, err := LoadIdentity(keyPath, "wrong-passphrase")
	if err == nil {
		t.Error("LoadIdentity should fail with wrong passphrase")
	}
}

func TestLoadIdentityFileNotFound(t *testing.T) {
	_, err := LoadIdentity("/nonexistent/path/keypair.enc", "passphrase")
	if err == nil {
		t.Error("LoadIdentity should fail for nonexistent file")
	}
}

func TestSaveIdentityCreatesParentDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "subdir", "nested", "keypair.enc")
	passphrase := "test-passphrase"

	identity, _ := GenerateIdentity()
	err := SaveIdentity(identity, keyPath, passphrase)
	if err != nil {
		t.Fatalf("SaveIdentity failed: %v", err)
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("Key file should exist in nested directory")
	}
}

func TestSaveAndLoadPreservesAllFields(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "keypair.enc")
	passphrase := "test-passphrase-456"

	original, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	err = SaveIdentity(original, keyPath, passphrase)
	if err != nil {
		t.Fatalf("SaveIdentity failed: %v", err)
	}

	loaded, err := LoadIdentity(keyPath, passphrase)
	if err != nil {
		t.Fatalf("LoadIdentity failed: %v", err)
	}

	// Verify all fields match
	if loaded.DID != original.DID {
		t.Errorf("DID mismatch: got %s, want %s", loaded.DID, original.DID)
	}
	if string(loaded.SigningKey) != string(original.SigningKey) {
		t.Error("SigningKey mismatch")
	}
	if string(loaded.VerifyKey) != string(original.VerifyKey) {
		t.Error("VerifyKey mismatch")
	}
	if string(loaded.EncryptionPrivate) != string(original.EncryptionPrivate) {
		t.Error("EncryptionPrivate mismatch")
	}
	if string(loaded.EncryptionPublic) != string(original.EncryptionPublic) {
		t.Error("EncryptionPublic mismatch")
	}
}

func TestLoadIdentityFileTooShort(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "short.enc")

	// Create a file that's too short (less than 28 bytes: 16 salt + 12 nonce)
	err := os.WriteFile(keyPath, make([]byte, 20), 0600)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	_, err = LoadIdentity(keyPath, "passphrase")
	if err == nil {
		t.Error("LoadIdentity should fail for file that's too short")
	}
}

func TestEmptyPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "keypair.enc")

	identity, _ := GenerateIdentity()

	// Should work with empty passphrase (though not recommended)
	err := SaveIdentity(identity, keyPath, "")
	if err != nil {
		t.Fatalf("SaveIdentity with empty passphrase failed: %v", err)
	}

	loaded, err := LoadIdentity(keyPath, "")
	if err != nil {
		t.Fatalf("LoadIdentity with empty passphrase failed: %v", err)
	}

	if loaded.DID != identity.DID {
		t.Error("DID mismatch with empty passphrase")
	}
}

package crypto

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/tyler-smith/go-bip39"
)

func TestNewIdentityWithMnemonic(t *testing.T) {
	identity, mnemonic, err := NewIdentityWithMnemonic()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mnemonic should be 24 words
	words := strings.Split(mnemonic, " ")
	if len(words) != 24 {
		t.Errorf("expected 24 words, got %d", len(words))
	}

	// Mnemonic should be valid
	if !bip39.IsMnemonicValid(mnemonic) {
		t.Error("mnemonic is not valid")
	}

	// Identity should be non-nil
	if identity == nil {
		t.Fatal("identity is nil")
	}

	if identity.SigningKey == nil {
		t.Error("signing key is nil")
	}

	if identity.DID == "" {
		t.Error("DID is empty")
	}
}

func TestGenerateIdentityFromMnemonic_Deterministic(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	id1, err := GenerateIdentityFromMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	id2, err := GenerateIdentityFromMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Same mnemonic should produce same identity
	if id1.DID != id2.DID {
		t.Errorf("DIDs don't match: %s vs %s", id1.DID, id2.DID)
	}
}

func TestGenerateIdentityFromMnemonic_InvalidMnemonic(t *testing.T) {
	_, err := GenerateIdentityFromMnemonic("invalid mnemonic words")
	if err == nil {
		t.Error("expected error for invalid mnemonic")
	}
	if err != ErrInvalidMnemonic {
		t.Errorf("expected ErrInvalidMnemonic, got: %v", err)
	}
}

func TestGenerateIdentityFromMnemonic_AllFieldsPopulated(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	identity, err := GenerateIdentityFromMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify all fields are populated
	if identity.SigningKey == nil {
		t.Error("SigningKey should not be nil")
	}
	if identity.VerifyKey == nil {
		t.Error("VerifyKey should not be nil")
	}
	if identity.EncryptionPrivate == nil {
		t.Error("EncryptionPrivate should not be nil")
	}
	if identity.EncryptionPublic == nil {
		t.Error("EncryptionPublic should not be nil")
	}
	if identity.DID == "" {
		t.Error("DID should not be empty")
	}

	// Verify key lengths
	if len(identity.SigningKey) != 64 {
		t.Errorf("SigningKey should be 64 bytes, got %d", len(identity.SigningKey))
	}
	if len(identity.VerifyKey) != 32 {
		t.Errorf("VerifyKey should be 32 bytes, got %d", len(identity.VerifyKey))
	}
	if len(identity.EncryptionPrivate) != 32 {
		t.Errorf("EncryptionPrivate should be 32 bytes, got %d", len(identity.EncryptionPrivate))
	}
	if len(identity.EncryptionPublic) != 32 {
		t.Errorf("EncryptionPublic should be 32 bytes, got %d", len(identity.EncryptionPublic))
	}
}

func TestGenerateIdentityFromMnemonic_DifferentMnemonicsDifferentIdentities(t *testing.T) {
	mnemonic1 := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	mnemonic2 := "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"

	id1, err := GenerateIdentityFromMnemonic(mnemonic1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	id2, err := GenerateIdentityFromMnemonic(mnemonic2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if id1.DID == id2.DID {
		t.Error("different mnemonics should produce different identities")
	}
}

func TestNewIdentityWithMnemonic_SigningCapability(t *testing.T) {
	identity, _, err := NewIdentityWithMnemonic()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify identity can sign and verify using ed25519 package functions
	message := []byte("test message")
	signature := ed25519.Sign(identity.SigningKey, message)
	if len(signature) == 0 {
		t.Fatal("signature is empty")
	}

	// Verify the signature
	if !ed25519.Verify(identity.VerifyKey, message, signature) {
		t.Error("signature verification failed")
	}
}

func TestNewIdentityWithMnemonic_X25519Capability(t *testing.T) {
	id1, _, err := NewIdentityWithMnemonic()
	if err != nil {
		t.Fatalf("unexpected error creating id1: %v", err)
	}

	id2, _, err := NewIdentityWithMnemonic()
	if err != nil {
		t.Fatalf("unexpected error creating id2: %v", err)
	}

	// Both should be able to derive the same shared secret
	shared1, err := id1.SharedSecret(id2.EncryptionPublic)
	if err != nil {
		t.Fatalf("id1 SharedSecret failed: %v", err)
	}

	shared2, err := id2.SharedSecret(id1.EncryptionPublic)
	if err != nil {
		t.Fatalf("id2 SharedSecret failed: %v", err)
	}

	if string(shared1) != string(shared2) {
		t.Error("shared secrets should match")
	}
}

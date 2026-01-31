package crypto

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/mr-tron/base58"
)

func TestGenerateIdentity(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	if identity.SigningKey == nil {
		t.Error("SigningKey should not be nil")
	}
	if identity.VerifyKey == nil {
		t.Error("VerifyKey should not be nil")
	}
	if len(identity.DID) == 0 {
		t.Error("DID should not be empty")
	}
}

func TestIdentityDIDFormat(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	// DID format: did:monad:<base58-pubkey>
	if len(identity.DID) < 15 {
		t.Errorf("DID too short: %s", identity.DID)
	}
	if identity.DID[:10] != "did:monad:" {
		t.Errorf("DID should start with 'did:monad:', got: %s", identity.DID)
	}
}

func TestIdentityKeyLengths(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	// Ed25519 public key is 32 bytes
	if len(identity.VerifyKey) != ed25519.PublicKeySize {
		t.Errorf("VerifyKey should be %d bytes, got %d", ed25519.PublicKeySize, len(identity.VerifyKey))
	}

	// Ed25519 private key is 64 bytes (seed + public key)
	if len(identity.SigningKey) != ed25519.PrivateKeySize {
		t.Errorf("SigningKey should be %d bytes, got %d", ed25519.PrivateKeySize, len(identity.SigningKey))
	}
}

func TestIdentityDIDContainsBase58EncodedPubkey(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	// Extract base58 portion from DID
	base58Part := strings.TrimPrefix(identity.DID, "did:monad:")

	// Decode the base58 portion
	decoded, err := base58.Decode(base58Part)
	if err != nil {
		t.Fatalf("Failed to decode base58 portion of DID: %v", err)
	}

	// Should match the public key
	if len(decoded) != len(identity.VerifyKey) {
		t.Errorf("Decoded DID length mismatch: got %d, want %d", len(decoded), len(identity.VerifyKey))
	}

	for i := range decoded {
		if decoded[i] != identity.VerifyKey[i] {
			t.Errorf("Decoded DID byte %d mismatch: got %d, want %d", i, decoded[i], identity.VerifyKey[i])
		}
	}
}

func TestIdentityUniqueness(t *testing.T) {
	// Generate multiple identities and ensure they're unique
	const numIdentities = 10
	dids := make(map[string]bool)

	for i := 0; i < numIdentities; i++ {
		identity, err := GenerateIdentity()
		if err != nil {
			t.Fatalf("GenerateIdentity failed on iteration %d: %v", i, err)
		}

		if dids[identity.DID] {
			t.Errorf("Duplicate DID generated: %s", identity.DID)
		}
		dids[identity.DID] = true
	}
}

func TestIdentitySigningCapability(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	// Sign a message
	message := []byte("test message for signing")
	signature := ed25519.Sign(identity.SigningKey, message)

	// Verify the signature
	if !ed25519.Verify(identity.VerifyKey, message, signature) {
		t.Error("Signature verification failed")
	}

	// Verify wrong message fails
	wrongMessage := []byte("wrong message")
	if ed25519.Verify(identity.VerifyKey, wrongMessage, signature) {
		t.Error("Signature should not verify for wrong message")
	}
}

func TestIdentityEncryptionKey(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	if identity.EncryptionPrivate == nil {
		t.Error("EncryptionPrivate should not be nil")
	}
	if identity.EncryptionPublic == nil {
		t.Error("EncryptionPublic should not be nil")
	}
	if len(identity.EncryptionPrivate) != 32 {
		t.Errorf("EncryptionPrivate should be 32 bytes, got %d", len(identity.EncryptionPrivate))
	}
	if len(identity.EncryptionPublic) != 32 {
		t.Errorf("EncryptionPublic should be 32 bytes, got %d", len(identity.EncryptionPublic))
	}
}

func TestX25519KeyExchange(t *testing.T) {
	alice, _ := GenerateIdentity()
	bob, _ := GenerateIdentity()

	// Both should derive the same shared secret
	sharedAlice, err := alice.SharedSecret(bob.EncryptionPublic)
	if err != nil {
		t.Fatalf("Alice SharedSecret failed: %v", err)
	}

	sharedBob, err := bob.SharedSecret(alice.EncryptionPublic)
	if err != nil {
		t.Fatalf("Bob SharedSecret failed: %v", err)
	}

	if string(sharedAlice) != string(sharedBob) {
		t.Error("Shared secrets should match")
	}
}

func TestSharedSecretInvalidPeerKey(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	// Test with wrong length peer public key
	invalidKeys := [][]byte{
		nil,
		{},
		make([]byte, 16),
		make([]byte, 31),
		make([]byte, 33),
		make([]byte, 64),
	}

	for _, invalidKey := range invalidKeys {
		_, err := identity.SharedSecret(invalidKey)
		if err == nil {
			t.Errorf("SharedSecret should fail for key of length %d", len(invalidKey))
		}
	}
}

func TestSharedSecretRejectsLowOrderPoints(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	// X25519 low-order points that should be rejected
	// These points have small subgroup order and produce weak shared secrets
	lowOrderPoints := [][]byte{
		// All zeros - identity element
		make([]byte, 32),
		// Point (1, 0)
		{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		// Small subgroup element of order 8
		{224, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9, 141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 0},
		// Another known low-order point
		{95, 156, 149, 188, 163, 80, 140, 36, 177, 208, 177, 85, 156, 131, 239, 91, 4, 68, 92, 196, 88, 28, 142, 134, 216, 34, 78, 221, 208, 159, 17, 87},
	}

	for i, lowOrderPoint := range lowOrderPoints {
		_, err := identity.SharedSecret(lowOrderPoint)
		if err == nil {
			t.Errorf("SharedSecret should reject low-order point %d", i)
		}
		if err != nil && err != ErrLowOrderPoint {
			t.Errorf("SharedSecret should return ErrLowOrderPoint for point %d, got: %v", i, err)
		}
	}
}

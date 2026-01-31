package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/mr-tron/base58"
	"golang.org/x/crypto/curve25519"
)

// ErrLowOrderPoint is returned when a low-order point is detected in X25519.
// Low-order points can lead to all-zeros or weak shared secrets.
var ErrLowOrderPoint = errors.New("crypto: low-order point detected")

// Identity holds the Ed25519 keypair, derived X25519 keys, and DID.
type Identity struct {
	// Signing (Ed25519)
	SigningKey ed25519.PrivateKey
	VerifyKey  ed25519.PublicKey

	// Encryption (X25519, derived from Ed25519)
	EncryptionPrivate []byte
	EncryptionPublic  []byte

	DID string
}

// GenerateIdentity creates a new Ed25519 keypair and derives X25519 keys.
func GenerateIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 keypair: %w", err)
	}

	// Derive X25519 keys from Ed25519 seed
	// Ed25519 private key is 64 bytes: 32-byte seed + 32-byte public key
	seed := priv.Seed()
	h := sha512.Sum512(seed)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64

	var encPrivate [32]byte
	copy(encPrivate[:], h[:32])

	var encPublic [32]byte
	curve25519.ScalarBaseMult(&encPublic, &encPrivate)

	did := "did:monad:" + base58.Encode(pub)

	return &Identity{
		SigningKey:        priv,
		VerifyKey:         pub,
		EncryptionPrivate: encPrivate[:],
		EncryptionPublic:  encPublic[:],
		DID:               did,
	}, nil
}

// SharedSecret computes X25519 shared secret with peer's public key.
// Returns ErrLowOrderPoint if the peer public key is a low-order point,
// which would produce a weak shared secret.
func (i *Identity) SharedSecret(peerPublic []byte) ([]byte, error) {
	if len(peerPublic) != 32 {
		return nil, fmt.Errorf("peer public key must be 32 bytes")
	}

	// Check for known low-order points before computation
	if isLowOrderPoint(peerPublic) {
		return nil, ErrLowOrderPoint
	}

	var privKey, pubKey, shared [32]byte
	copy(privKey[:], i.EncryptionPrivate)
	copy(pubKey[:], peerPublic)

	curve25519.ScalarMult(&shared, &privKey, &pubKey)

	// Check if shared secret is all zeros (can happen with some low-order inputs)
	var zeros [32]byte
	if subtle.ConstantTimeCompare(shared[:], zeros[:]) == 1 {
		return nil, ErrLowOrderPoint
	}

	return shared[:], nil
}

// isLowOrderPoint checks if the given X25519 public key is a known low-order point.
// Low-order points have small subgroup order and can produce weak shared secrets.
func isLowOrderPoint(pubKey []byte) bool {
	if len(pubKey) != 32 {
		return false
	}

	// Known low-order points in X25519 (little-endian representation)
	lowOrderPoints := [][32]byte{
		// All zeros - identity element
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		// Point (1, 0) - order 1
		{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		// Order 8 point
		{224, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9, 141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 0},
		// Order 8 point (another representation)
		{95, 156, 149, 188, 163, 80, 140, 36, 177, 208, 177, 85, 156, 131, 239, 91, 4, 68, 92, 196, 88, 28, 142, 134, 216, 34, 78, 221, 208, 159, 17, 87},
		// Order 4 point
		{236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		// Order 8 point (another)
		{38, 232, 149, 143, 194, 178, 39, 176, 69, 195, 244, 137, 242, 239, 152, 240, 213, 223, 172, 5, 211, 198, 51, 57, 177, 56, 2, 136, 109, 83, 252, 5},
	}

	var key [32]byte
	copy(key[:], pubKey)

	for _, lowOrder := range lowOrderPoints {
		if subtle.ConstantTimeCompare(key[:], lowOrder[:]) == 1 {
			return true
		}
	}

	return false
}

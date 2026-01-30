package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"fmt"

	"github.com/mr-tron/base58"
	"golang.org/x/crypto/curve25519"
)

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
func (i *Identity) SharedSecret(peerPublic []byte) ([]byte, error) {
	if len(peerPublic) != 32 {
		return nil, fmt.Errorf("peer public key must be 32 bytes")
	}

	var privKey, pubKey, shared [32]byte
	copy(privKey[:], i.EncryptionPrivate)
	copy(pubKey[:], peerPublic)

	curve25519.ScalarMult(&shared, &privKey, &pubKey)

	return shared[:], nil
}

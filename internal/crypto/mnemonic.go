package crypto

import (
	"crypto/ed25519"
	"crypto/sha512"
	"errors"

	"github.com/mr-tron/base58"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/curve25519"
)

// ErrInvalidMnemonic is returned when an invalid BIP-39 mnemonic phrase is provided.
var ErrInvalidMnemonic = errors.New("crypto: invalid mnemonic phrase")

// NewIdentityWithMnemonic generates a new identity with a BIP-39 mnemonic for recovery.
// The mnemonic is 24 words and should be written down by the user.
// Returns the identity and the mnemonic string.
func NewIdentityWithMnemonic() (*Identity, string, error) {
	entropy, err := bip39.NewEntropy(256) // 24 words
	if err != nil {
		return nil, "", err
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, "", err
	}

	identity, err := GenerateIdentityFromMnemonic(mnemonic)
	if err != nil {
		return nil, "", err
	}

	return identity, mnemonic, nil
}

// GenerateIdentityFromMnemonic recovers an identity from a BIP-39 mnemonic.
// This is deterministic - the same mnemonic always produces the same identity.
func GenerateIdentityFromMnemonic(mnemonic string) (*Identity, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, ErrInvalidMnemonic
	}

	// Derive seed from mnemonic (no passphrase)
	seed := bip39.NewSeed(mnemonic, "")

	// Use first 32 bytes as Ed25519 seed
	privateKey := ed25519.NewKeyFromSeed(seed[:32])
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Derive X25519 keys from Ed25519 seed (same as GenerateIdentity)
	h := sha512.Sum512(seed[:32])
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64

	var encPrivate [32]byte
	copy(encPrivate[:], h[:32])

	var encPublic [32]byte
	curve25519.ScalarBaseMult(&encPublic, &encPrivate)

	did := "did:monad:" + base58.Encode(publicKey)

	return &Identity{
		SigningKey:        privateKey,
		VerifyKey:         publicKey,
		EncryptionPrivate: encPrivate[:],
		EncryptionPublic:  encPublic[:],
		DID:               did,
	}, nil
}

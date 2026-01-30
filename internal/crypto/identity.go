package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/mr-tron/base58"
)

// Identity holds the Ed25519 keypair and derived DID.
type Identity struct {
	SigningKey ed25519.PrivateKey
	VerifyKey  ed25519.PublicKey
	DID        string
}

// GenerateIdentity creates a new Ed25519 keypair and derives the DID.
func GenerateIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 keypair: %w", err)
	}

	did := "did:monad:" + base58.Encode(pub)

	return &Identity{
		SigningKey: priv,
		VerifyKey:  pub,
		DID:        did,
	}, nil
}

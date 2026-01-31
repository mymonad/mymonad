// Package hashcash provides Proof-of-Work challenge generation and verification
// for spam prevention in the MyMonad P2P protocol.
//
// Hashcash is a computational puzzle that requires the initiator to perform
// work before starting a handshake, making mass spam expensive. The protocol
// uses a format similar to the original Hashcash email spam prevention system.
//
// Challenge format: version:bits:timestamp:resource:rand
// Example: 1:20:1706745600:did:monad:abc123:MTIzNDU2
package hashcash

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Default values for challenge creation.
const (
	// DefaultBits is the default difficulty (leading zero bits required).
	// 20 bits requires approximately 1 second to solve on a modern CPU.
	DefaultBits = 20

	// DefaultExpiration is the default challenge validity duration.
	DefaultExpiration = 5 * time.Minute

	// RandSize is the number of random bytes in a challenge (128 bits entropy).
	RandSize = 16

	// CurrentVersion is the only supported hashcash version.
	CurrentVersion = 1
)

// Errors returned by hashcash operations.
var (
	// ErrInvalidFormat is returned when a challenge string cannot be parsed.
	ErrInvalidFormat = errors.New("hashcash: invalid challenge format")

	// ErrUnsupportedVersion is returned when the challenge version is not supported.
	ErrUnsupportedVersion = errors.New("hashcash: unsupported version")

	// ErrInvalidBits is returned when bits value is invalid.
	ErrInvalidBits = errors.New("hashcash: invalid bits value")

	// ErrEmptyRand is returned when the random component is empty.
	ErrEmptyRand = errors.New("hashcash: empty random component")

	// ErrZeroExpiration is returned when the expiration duration is zero.
	ErrZeroExpiration = errors.New("hashcash: zero expiration duration")
)

// Challenge represents a hashcash proof-of-work challenge.
// The initiating peer must find a counter value such that the hash of
// the challenge string with the counter has the required number of leading
// zero bits.
type Challenge struct {
	// Version is the hashcash version (currently always 1).
	Version int

	// Bits is the difficulty level - number of leading zero bits required
	// in the hash. Higher values = more computational work required.
	Bits int

	// Timestamp is when the challenge was created.
	// Used to verify the challenge hasn't expired.
	Timestamp time.Time

	// Resource identifies what we're protecting (e.g., peer ID, endpoint).
	// Prevents challenge reuse across different resources.
	Resource string

	// Rand is a base64-encoded random value that prevents pre-computation.
	// Generated using crypto/rand for cryptographic security.
	Rand string

	// Expiration is how long the challenge remains valid after creation.
	// Not serialized into the challenge string - set during parsing or creation.
	Expiration time.Duration
}

// NewChallenge creates a new Challenge with the specified parameters.
// The random component is generated using crypto/rand.
func NewChallenge(resource string, bits int, expiration time.Duration) *Challenge {
	// Generate random bytes
	randBytes := make([]byte, RandSize)
	if _, err := rand.Read(randBytes); err != nil {
		// crypto/rand.Read should never fail on modern systems,
		// but if it does, we panic as this is a critical security failure.
		panic(fmt.Sprintf("hashcash: crypto/rand.Read failed: %v", err))
	}

	return &Challenge{
		Version:    CurrentVersion,
		Bits:       bits,
		Timestamp:  time.Now().UTC(),
		Resource:   resource,
		Rand:       base64.StdEncoding.EncodeToString(randBytes),
		Expiration: expiration,
	}
}

// NewDefaultChallenge creates a new Challenge with default bits and expiration.
func NewDefaultChallenge(resource string) *Challenge {
	return NewChallenge(resource, DefaultBits, DefaultExpiration)
}

// String serializes the Challenge to hashcash format.
// Format: version:bits:timestamp:resource:rand
//
// Note: The resource field may contain colons (e.g., DIDs like "did:monad:xyz").
// When parsing, we split into exactly 5 parts - version, bits, timestamp,
// and then reconstruct resource by joining the remaining parts except the last.
func (c *Challenge) String() string {
	return fmt.Sprintf("%d:%d:%d:%s:%s",
		c.Version,
		c.Bits,
		c.Timestamp.Unix(),
		c.Resource,
		c.Rand,
	)
}

// ParseChallenge deserializes a hashcash challenge string.
// The expiration field is set to DefaultExpiration since it's not encoded
// in the string format.
func ParseChallenge(s string) (*Challenge, error) {
	if s == "" {
		return nil, ErrInvalidFormat
	}

	// Split the string by colons
	// Format: version:bits:timestamp:resource:rand
	// Note: resource may contain colons, so we need careful handling
	parts := strings.Split(s, ":")

	// We need at least 5 parts: version, bits, timestamp, resource (may be empty), rand
	if len(parts) < 5 {
		return nil, ErrInvalidFormat
	}

	// Too many parts means extra colons that we can't handle
	// Actually, the resource can contain colons, so we need a different approach:
	// version:bits:timestamp:[resource-with-colons]:rand
	// The rand is always the last part (base64, no colons)
	// So we take first 3 parts, last part, and join the middle

	// Parse version (first part)
	version, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, ErrInvalidFormat
	}
	if version < 1 {
		return nil, ErrInvalidFormat
	}
	if version != CurrentVersion {
		return nil, ErrUnsupportedVersion
	}

	// Parse bits (second part)
	bits, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, ErrInvalidFormat
	}
	if bits <= 0 {
		return nil, ErrInvalidFormat
	}

	// Parse timestamp (third part)
	timestamp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return nil, ErrInvalidFormat
	}

	// Rand is the last part
	randStr := parts[len(parts)-1]

	// Resource is everything between timestamp and rand
	// Join parts[3] through parts[len(parts)-2] with colons
	var resource string
	if len(parts) == 5 {
		resource = parts[3]
	} else {
		// Multiple colons in resource
		resource = strings.Join(parts[3:len(parts)-1], ":")
	}

	return &Challenge{
		Version:    version,
		Bits:       bits,
		Timestamp:  time.Unix(timestamp, 0).UTC(),
		Resource:   resource,
		Rand:       randStr,
		Expiration: DefaultExpiration,
	}, nil
}

// IsExpired returns true if the challenge has expired.
// A challenge is expired if the current time is past Timestamp + Expiration.
func (c *Challenge) IsExpired() bool {
	return time.Now().After(c.Timestamp.Add(c.Expiration))
}

// Validate checks if the challenge is well-formed.
// Returns an error describing the validation failure, or nil if valid.
func (c *Challenge) Validate() error {
	if c.Version != CurrentVersion {
		return ErrUnsupportedVersion
	}
	if c.Bits <= 0 {
		return ErrInvalidBits
	}
	if c.Rand == "" {
		return ErrEmptyRand
	}
	if c.Expiration <= 0 {
		return ErrZeroExpiration
	}
	return nil
}

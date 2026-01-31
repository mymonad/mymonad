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
	"bytes"
	"crypto/rand"
	"crypto/sha256"
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

	// MaxIterations is the maximum number of iterations before Solve gives up.
	// 2^32 iterations should be sufficient for any reasonable difficulty.
	MaxIterations = 1 << 32
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

	// ErrNilChallenge is returned when a nil challenge is passed to Solve.
	ErrNilChallenge = errors.New("hashcash: nil challenge")

	// ErrMaxIterationsExceeded is returned when Solve exceeds the maximum iterations.
	ErrMaxIterationsExceeded = errors.New("hashcash: max iterations exceeded")

	// ErrInvalidSolutionFormat is returned when a solution string cannot be parsed.
	ErrInvalidSolutionFormat = errors.New("hashcash: invalid solution format")
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

// Solution represents a solved hashcash proof-of-work challenge.
// It contains the original challenge, the nonce (counter) that produces
// a valid hash, and the resulting hash.
type Solution struct {
	// Challenge is the original challenge that was solved.
	Challenge *Challenge

	// Counter is the nonce value that, when appended to the challenge string,
	// produces a hash with the required number of leading zero bits.
	Counter int64

	// Hash is the SHA-256 hash of "challenge:counter" that has the required
	// leading zeros. Stored for quick verification without rehashing.
	Hash []byte
}

// Solve finds a nonce (counter) that produces a hash with the required
// number of leading zero bits for the given challenge.
//
// The algorithm iterates from 0, computing SHA-256(challenge_string:counter)
// until finding a hash with the required leading zeros.
//
// Returns ErrNilChallenge if the challenge is nil.
// Returns ErrMaxIterationsExceeded if no solution is found within MaxIterations.
func Solve(c *Challenge) (*Solution, error) {
	return SolveWithMaxIterations(c, MaxIterations)
}

// SolveWithMaxIterations is like Solve but with a configurable maximum iteration count.
// This is useful for testing or when you want to limit computation time.
func SolveWithMaxIterations(c *Challenge, maxIterations int64) (*Solution, error) {
	if c == nil {
		return nil, ErrNilChallenge
	}

	challengeStr := c.String()

	// Pre-allocate buffer for challenge:counter strings to reduce allocations
	// Max int64 is 19 digits, plus colon = 20 extra bytes
	buf := make([]byte, 0, len(challengeStr)+21)
	buf = append(buf, challengeStr...)
	buf = append(buf, ':')
	prefixLen := len(buf)

	for counter := int64(0); counter < maxIterations; counter++ {
		// Reuse buffer: truncate to prefix and append counter
		buf = buf[:prefixLen]
		buf = strconv.AppendInt(buf, counter, 10)

		hash := sha256.Sum256(buf)

		if hasLeadingZeros(hash[:], c.Bits) {
			return &Solution{
				Challenge: c,
				Counter:   counter,
				Hash:      hash[:],
			}, nil
		}
	}

	return nil, ErrMaxIterationsExceeded
}

// Verify checks if the solution is valid for its challenge.
// A solution is valid if:
// 1. The challenge is not nil
// 2. The hash of "challenge:counter" equals the stored hash
// 3. The hash has the required number of leading zero bits
//
// Returns false if any verification step fails.
func (s *Solution) Verify() bool {
	if s.Challenge == nil {
		return false
	}

	// Recompute the hash
	data := fmt.Sprintf("%s:%d", s.Challenge.String(), s.Counter)
	hash := sha256.Sum256([]byte(data))

	// Verify hash matches stored hash
	if !bytes.Equal(hash[:], s.Hash) {
		return false
	}

	// Verify leading zeros
	return hasLeadingZeros(hash[:], s.Challenge.Bits)
}

// String serializes the Solution to hashcash format.
// Format: challenge_string:counter
// Example: 1:20:1706745600:did:monad:abc123:MTIzNDU2:12345
//
// Returns empty string if the challenge is nil.
func (s *Solution) String() string {
	if s.Challenge == nil {
		return ""
	}
	return fmt.Sprintf("%s:%d", s.Challenge.String(), s.Counter)
}

// ParseSolution parses a solution string and computes its hash.
// Format: version:bits:timestamp:resource:rand:counter
//
// The hash is computed from the solution string, not stored in the string.
func ParseSolution(str string) (*Solution, error) {
	if str == "" {
		return nil, ErrInvalidSolutionFormat
	}

	// Find the last colon - everything after is the counter
	lastColonIdx := strings.LastIndex(str, ":")
	if lastColonIdx == -1 {
		return nil, ErrInvalidSolutionFormat
	}

	challengeStr := str[:lastColonIdx]
	counterStr := str[lastColonIdx+1:]

	// Parse the counter
	counter, err := strconv.ParseInt(counterStr, 10, 64)
	if err != nil {
		return nil, ErrInvalidSolutionFormat
	}
	if counter < 0 {
		return nil, ErrInvalidSolutionFormat
	}

	// Parse the challenge
	challenge, err := ParseChallenge(challengeStr)
	if err != nil {
		return nil, err
	}

	// Compute the hash
	hash := sha256.Sum256([]byte(str))

	return &Solution{
		Challenge: challenge,
		Counter:   counter,
		Hash:      hash[:],
	}, nil
}

// hasLeadingZeros checks if a hash has at least the specified number of
// leading zero bits.
//
// For example, if bits=20, the first 20 bits of the hash must be 0.
// This is checked by examining full bytes first, then the remaining bits.
func hasLeadingZeros(hash []byte, bits int) bool {
	if bits <= 0 {
		return true
	}

	// Check full bytes first
	fullBytes := bits / 8
	for i := 0; i < fullBytes; i++ {
		if i >= len(hash) {
			return false
		}
		if hash[i] != 0 {
			return false
		}
	}

	// Check remaining bits
	remainingBits := bits % 8
	if remainingBits > 0 {
		if fullBytes >= len(hash) {
			return false
		}
		// Create a mask for the remaining bits
		// For 4 remaining bits: 0xF0 (1111 0000)
		// For 3 remaining bits: 0xE0 (1110 0000)
		// For 1 remaining bit:  0x80 (1000 0000)
		mask := byte(0xFF << (8 - remainingBits))
		if hash[fullBytes]&mask != 0 {
			return false
		}
	}

	return true
}

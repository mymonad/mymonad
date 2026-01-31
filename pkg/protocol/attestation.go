// Package protocol implements the MyMonad handshake protocol for agent matching.
package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mymonad/mymonad/pkg/hashcash"
)

// Attestation errors.
var (
	// ErrInvalidDifficulty is returned when the difficulty is invalid.
	ErrInvalidDifficulty = errors.New("attestation: difficulty must be positive")

	// ErrInvalidChallenge is returned when the challenge cannot be parsed.
	ErrInvalidChallenge = errors.New("attestation: invalid challenge format")

	// ErrSignatureRequired is returned when a signature is missing.
	ErrSignatureRequired = errors.New("attestation: signature required")

	// ErrInvalidSignature is returned when signature verification fails.
	ErrInvalidSignature = errors.New("attestation: invalid signature")

	// ErrPoWSolveFailed is returned when PoW solving fails.
	ErrPoWSolveFailed = errors.New("attestation: failed to solve PoW challenge")
)

// AttestationRequest represents a request sent during the attestation stage.
// The initiator sends this to the responder, including a hashcash challenge
// that the responder must solve to prove they're willing to expend resources.
type AttestationRequest struct {
	// Version is the MyMonad protocol version.
	Version string

	// PeerID is the sender's libp2p peer ID.
	PeerID peer.ID

	// Challenge is the hashcash challenge string for the responder to solve.
	// Format: version:bits:timestamp:resource:rand
	Challenge string

	// Timestamp is when the request was created.
	Timestamp time.Time

	// Signature is the Ed25519 signature over the request content.
	Signature []byte
}

// AttestationResponse represents a response to an attestation request.
// The responder sends this after solving the hashcash challenge.
type AttestationResponse struct {
	// Version is the MyMonad protocol version.
	Version string

	// PeerID is the responder's libp2p peer ID.
	PeerID peer.ID

	// Solution is the solved hashcash challenge (challenge + ":" + counter).
	Solution string

	// Timestamp is when the response was created.
	Timestamp time.Time

	// Signature is the Ed25519 signature over the response content.
	Signature []byte
}

// NewAttestationRequest creates a new attestation request with a fresh challenge.
// The difficulty parameter specifies the number of leading zero bits required
// in the hashcash solution.
func NewAttestationRequest(peerID peer.ID, version string, difficulty int) (*AttestationRequest, error) {
	if difficulty <= 0 {
		return nil, ErrInvalidDifficulty
	}

	// Create a hashcash challenge using the peer ID as the resource
	challenge := hashcash.NewChallenge(string(peerID), difficulty, hashcash.DefaultExpiration)

	return &AttestationRequest{
		Version:   version,
		PeerID:    peerID,
		Challenge: challenge.String(),
		Timestamp: time.Now().UTC(),
	}, nil
}

// BytesToSign returns the bytes that should be signed for this request.
// This includes version, peerID, challenge, and timestamp but NOT the signature.
func (r *AttestationRequest) BytesToSign() []byte {
	// Create a deterministic byte representation
	// Format: version | peerID | challenge | timestamp (unix seconds as 8-byte big-endian)
	var buf []byte

	buf = append(buf, []byte(r.Version)...)
	buf = append(buf, 0) // separator
	buf = append(buf, []byte(r.PeerID)...)
	buf = append(buf, 0) // separator
	buf = append(buf, []byte(r.Challenge)...)
	buf = append(buf, 0) // separator

	// Timestamp as 8-byte big-endian
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(r.Timestamp.Unix()))
	buf = append(buf, timestampBytes...)

	return buf
}

// Sign signs the request with the given Ed25519 private key.
func (r *AttestationRequest) Sign(privateKey ed25519.PrivateKey) error {
	r.Signature = ed25519.Sign(privateKey, r.BytesToSign())
	return nil
}

// Verify verifies the request signature using the given Ed25519 public key.
func (r *AttestationRequest) Verify(publicKey ed25519.PublicKey) error {
	if len(r.Signature) == 0 {
		return ErrSignatureRequired
	}

	if !ed25519.Verify(publicKey, r.BytesToSign(), r.Signature) {
		return ErrInvalidSignature
	}

	return nil
}

// NewAttestationResponse creates a new attestation response by solving
// the provided hashcash challenge.
func NewAttestationResponse(peerID peer.ID, version string, challenge string) (*AttestationResponse, error) {
	if challenge == "" {
		return nil, ErrInvalidChallenge
	}

	// Parse the challenge to validate it
	parsedChallenge, err := hashcash.ParseChallenge(challenge)
	if err != nil {
		return nil, ErrInvalidChallenge
	}

	// Solve the challenge
	solution, err := solveHashcash(parsedChallenge)
	if err != nil {
		return nil, ErrPoWSolveFailed
	}

	return &AttestationResponse{
		Version:   version,
		PeerID:    peerID,
		Solution:  solution,
		Timestamp: time.Now().UTC(),
	}, nil
}

// BytesToSign returns the bytes that should be signed for this response.
// This includes version, peerID, solution, and timestamp but NOT the signature.
func (r *AttestationResponse) BytesToSign() []byte {
	// Create a deterministic byte representation
	// Format: version | peerID | solution | timestamp (unix seconds as 8-byte big-endian)
	var buf []byte

	buf = append(buf, []byte(r.Version)...)
	buf = append(buf, 0) // separator
	buf = append(buf, []byte(r.PeerID)...)
	buf = append(buf, 0) // separator
	buf = append(buf, []byte(r.Solution)...)
	buf = append(buf, 0) // separator

	// Timestamp as 8-byte big-endian
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(r.Timestamp.Unix()))
	buf = append(buf, timestampBytes...)

	return buf
}

// Sign signs the response with the given Ed25519 private key.
func (r *AttestationResponse) Sign(privateKey ed25519.PrivateKey) error {
	r.Signature = ed25519.Sign(privateKey, r.BytesToSign())
	return nil
}

// Verify verifies the response signature using the given Ed25519 public key.
func (r *AttestationResponse) Verify(publicKey ed25519.PublicKey) error {
	if len(r.Signature) == 0 {
		return ErrSignatureRequired
	}

	if !ed25519.Verify(publicKey, r.BytesToSign(), r.Signature) {
		return ErrInvalidSignature
	}

	return nil
}

// VerifyPoW verifies that the solution has valid proof-of-work at the given difficulty.
// The difficulty is the number of leading zero bits required in the hash.
func (r *AttestationResponse) VerifyPoW(difficulty int) bool {
	if r.Solution == "" {
		return false
	}

	// Parse the solution to extract difficulty from it
	// Solution format: version:bits:timestamp:resource:rand:counter
	parts := strings.Split(r.Solution, ":")
	if len(parts) < 6 {
		return false
	}

	// Hash the solution and check leading zero bits
	hash := sha256.Sum256([]byte(r.Solution))
	return hasLeadingZeroBits(hash[:], difficulty)
}

// solveHashcash finds a counter that produces the required number of leading zero bits.
func solveHashcash(challenge *hashcash.Challenge) (string, error) {
	challengeStr := challenge.String()

	// Try counters until we find one that produces enough leading zero bits
	for counter := uint64(0); counter < 1<<40; counter++ { // Limit iterations
		solution := challengeStr + ":" + strconv.FormatUint(counter, 10)
		hash := sha256.Sum256([]byte(solution))

		if hasLeadingZeroBits(hash[:], challenge.Bits) {
			return solution, nil
		}
	}

	return "", ErrPoWSolveFailed
}

// hasLeadingZeroBits checks if the hash has at least n leading zero bits.
func hasLeadingZeroBits(hash []byte, n int) bool {
	if n <= 0 {
		return true
	}

	// Check full bytes first
	fullBytes := n / 8
	remainingBits := n % 8

	// Check that we have enough bytes
	if fullBytes >= len(hash) {
		return false
	}

	// Check full zero bytes
	for i := 0; i < fullBytes; i++ {
		if hash[i] != 0 {
			return false
		}
	}

	// Check remaining bits in the next byte
	if remainingBits > 0 {
		// Create a mask for the remaining bits
		// For example, if remainingBits is 3, mask is 0b11100000 = 0xE0
		mask := byte(0xFF << (8 - remainingBits))
		if hash[fullBytes]&mask != 0 {
			return false
		}
	}

	return true
}

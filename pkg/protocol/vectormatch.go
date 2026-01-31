// Package protocol implements the MyMonad handshake protocol for agent matching.
package protocol

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"math"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// Vector match errors.
var (
	// ErrInvalidMonadData is returned when the monad data cannot be decoded.
	ErrInvalidMonadData = errors.New("vectormatch: invalid monad data format")

	// ErrVectorDimensionMismatch is returned when vectors have different dimensions.
	ErrVectorDimensionMismatch = errors.New("vectormatch: vector dimension mismatch")

	// ErrVectorMatchSignatureRequired is returned when a signature is missing.
	ErrVectorMatchSignatureRequired = errors.New("vectormatch: signature required")

	// ErrVectorMatchInvalidSignature is returned when signature verification fails.
	ErrVectorMatchInvalidSignature = errors.New("vectormatch: invalid signature")
)

// VectorMatchRequest represents a request sent during the vector match stage.
// The initiator sends their encrypted monad to be compared against the responder's
// monad in a Trusted Execution Environment (TEE).
type VectorMatchRequest struct {
	// PeerID is the sender's libp2p peer ID.
	PeerID peer.ID

	// EncryptedMonad is the monad encrypted for the TEE.
	// In v1 with MockTEE, this is the raw encoded vector.
	// In production with real TEE, this would be encrypted with the TEE's public key.
	EncryptedMonad []byte

	// Timestamp is when the request was created.
	Timestamp time.Time

	// Signature is the Ed25519 signature over the request content.
	Signature []byte
}

// VectorMatchResponse represents a response to a vector match request.
// The responder sends the similarity score computed by the TEE.
type VectorMatchResponse struct {
	// PeerID is the responder's libp2p peer ID.
	PeerID peer.ID

	// Score is the cosine similarity computed by the TEE.
	// Range: -1.0 to 1.0 (typically 0.0 to 1.0 for normalized vectors).
	Score float32

	// Matched indicates whether the score meets or exceeds the threshold.
	Matched bool

	// Timestamp is when the response was created.
	Timestamp time.Time

	// Signature is the Ed25519 signature over the response content.
	Signature []byte
}

// NewVectorMatchRequest creates a new vector match request with the given
// peer ID and encrypted monad data.
func NewVectorMatchRequest(peerID peer.ID, encryptedMonad []byte) *VectorMatchRequest {
	return &VectorMatchRequest{
		PeerID:         peerID,
		EncryptedMonad: encryptedMonad,
		Timestamp:      time.Now().UTC(),
	}
}

// BytesToSign returns the bytes that should be signed for this request.
// This includes peerID, encryptedMonad, and timestamp but NOT the signature.
func (r *VectorMatchRequest) BytesToSign() []byte {
	// Create a deterministic byte representation
	// Format: peerID | encryptedMonad | timestamp (unix seconds as 8-byte big-endian)
	var buf []byte

	buf = append(buf, []byte(r.PeerID)...)
	buf = append(buf, 0) // separator
	buf = append(buf, r.EncryptedMonad...)
	buf = append(buf, 0) // separator

	// Timestamp as 8-byte big-endian
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(r.Timestamp.Unix()))
	buf = append(buf, timestampBytes...)

	return buf
}

// Sign signs the request with the given Ed25519 private key.
func (r *VectorMatchRequest) Sign(privateKey ed25519.PrivateKey) error {
	r.Signature = ed25519.Sign(privateKey, r.BytesToSign())
	return nil
}

// Verify verifies the request signature using the given Ed25519 public key.
func (r *VectorMatchRequest) Verify(publicKey ed25519.PublicKey) error {
	if len(r.Signature) == 0 {
		return ErrVectorMatchSignatureRequired
	}

	if !ed25519.Verify(publicKey, r.BytesToSign(), r.Signature) {
		return ErrVectorMatchInvalidSignature
	}

	return nil
}

// NewVectorMatchResponse creates a new vector match response with the given
// peer ID, similarity score, and matching threshold.
// Matched is set to true if score >= threshold.
func NewVectorMatchResponse(peerID peer.ID, score float32, threshold float32) *VectorMatchResponse {
	return &VectorMatchResponse{
		PeerID:    peerID,
		Score:     score,
		Matched:   score >= threshold,
		Timestamp: time.Now().UTC(),
	}
}

// BytesToSign returns the bytes that should be signed for this response.
// This includes peerID, score, matched, and timestamp but NOT the signature.
func (r *VectorMatchResponse) BytesToSign() []byte {
	// Create a deterministic byte representation
	// Format: peerID | score (4-byte float32) | matched (1-byte bool) | timestamp (8-byte big-endian)
	var buf []byte

	buf = append(buf, []byte(r.PeerID)...)
	buf = append(buf, 0) // separator

	// Score as 4-byte big-endian float32 bits
	scoreBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(scoreBytes, math.Float32bits(r.Score))
	buf = append(buf, scoreBytes...)
	buf = append(buf, 0) // separator

	// Matched as 1-byte bool
	if r.Matched {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	buf = append(buf, 0) // separator

	// Timestamp as 8-byte big-endian
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(r.Timestamp.Unix()))
	buf = append(buf, timestampBytes...)

	return buf
}

// Sign signs the response with the given Ed25519 private key.
func (r *VectorMatchResponse) Sign(privateKey ed25519.PrivateKey) error {
	r.Signature = ed25519.Sign(privateKey, r.BytesToSign())
	return nil
}

// Verify verifies the response signature using the given Ed25519 public key.
func (r *VectorMatchResponse) Verify(publicKey ed25519.PublicKey) error {
	if len(r.Signature) == 0 {
		return ErrVectorMatchSignatureRequired
	}

	if !ed25519.Verify(publicKey, r.BytesToSign(), r.Signature) {
		return ErrVectorMatchInvalidSignature
	}

	return nil
}

// MockTEE is a mock Trusted Execution Environment for development.
// In v1, it decrypts and computes similarity locally.
// Real TEE integration (Intel SGX) is deferred to Phase 12.
type MockTEE struct{}

// NewMockTEE creates a new MockTEE instance.
func NewMockTEE() *MockTEE {
	return &MockTEE{}
}

// ComputeSimilarity computes the cosine similarity between two encoded monads.
// For the mock TEE, monads are expected to be encoded vectors (not encrypted).
// Returns a score in the range [-1.0, 1.0].
func (t *MockTEE) ComputeSimilarity(monadA, monadB []byte) (float32, error) {
	// Decode the vectors
	vecA, err := decodeVector(monadA)
	if err != nil {
		return 0, err
	}

	vecB, err := decodeVector(monadB)
	if err != nil {
		return 0, err
	}

	// Check dimensions match
	if len(vecA) != len(vecB) {
		return 0, ErrVectorDimensionMismatch
	}

	// Compute cosine similarity
	return cosineSimilarity(vecA, vecB), nil
}

// decodeVector decodes a byte slice into a float32 vector.
// Format: [num_dims as uint32 big-endian][float32 big-endian...]
func decodeVector(data []byte) ([]float32, error) {
	if len(data) < 4 {
		return nil, ErrInvalidMonadData
	}

	// Read number of dimensions
	numDims := int(binary.BigEndian.Uint32(data[:4]))

	// Verify data length
	expectedLen := 4 + numDims*4
	if len(data) != expectedLen {
		return nil, ErrInvalidMonadData
	}

	// Decode float32 values
	vec := make([]float32, numDims)
	for i := 0; i < numDims; i++ {
		offset := 4 + i*4
		bits := binary.BigEndian.Uint32(data[offset : offset+4])
		vec[i] = math.Float32frombits(bits)
	}

	return vec, nil
}

// cosineSimilarity computes the cosine similarity between two vectors.
// Returns 0.0 if either vector is zero-length.
func cosineSimilarity(a, b []float32) float32 {
	var dot, normA, normB float64
	for i := range a {
		av := float64(a[i])
		bv := float64(b[i])
		dot += av * bv
		normA += av * av
		normB += bv * bv
	}

	if normA == 0 || normB == 0 {
		return 0
	}

	return float32(dot / (math.Sqrt(normA) * math.Sqrt(normB)))
}

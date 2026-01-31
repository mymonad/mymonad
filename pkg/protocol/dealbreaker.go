// Package protocol implements the MyMonad handshake protocol for agent matching.
package protocol

import (
	"crypto/ed25519"
	"encoding/binary"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// DealBreaker represents a yes/no question with an expected answer.
// Both peers exchange exactly 3 deal-breakers that must all match.
type DealBreaker struct {
	// Question is the yes/no question text.
	Question string
	// Answer is the expected answer (true = yes, false = no).
	Answer bool
}

// DealBreakerRequest is sent during the deal-breaker exchange stage.
// Each peer sends their 3 questions with expected answers.
type DealBreakerRequest struct {
	// PeerID is the sender's libp2p peer ID.
	PeerID peer.ID

	// Questions contains exactly 3 deal-breaker questions with expected answers.
	Questions [3]DealBreaker

	// Timestamp is when the request was created.
	Timestamp time.Time

	// Signature is the Ed25519 signature over the request content.
	Signature []byte
}

// DealBreakerResponse contains answers to the peer's deal-breaker questions.
type DealBreakerResponse struct {
	// PeerID is the responder's libp2p peer ID.
	PeerID peer.ID

	// Answers contains exactly 3 answers to the peer's questions.
	Answers [3]bool

	// Matched is true if all answers match the peer's expectations.
	Matched bool

	// Timestamp is when the response was created.
	Timestamp time.Time

	// Signature is the Ed25519 signature over the response content.
	Signature []byte
}

// NewDealBreakerRequest creates a new deal-breaker request with the given questions.
func NewDealBreakerRequest(peerID peer.ID, questions [3]DealBreaker) *DealBreakerRequest {
	return &DealBreakerRequest{
		PeerID:    peerID,
		Questions: questions,
		Timestamp: time.Now().UTC(),
	}
}

// BytesToSign returns the bytes that should be signed for this request.
// This includes peerID, questions, and timestamp but NOT the signature.
func (r *DealBreakerRequest) BytesToSign() []byte {
	var buf []byte

	// PeerID
	buf = append(buf, []byte(r.PeerID)...)
	buf = append(buf, 0) // separator

	// Questions
	for i := 0; i < 3; i++ {
		buf = append(buf, []byte(r.Questions[i].Question)...)
		buf = append(buf, 0) // separator
		if r.Questions[i].Answer {
			buf = append(buf, 1)
		} else {
			buf = append(buf, 0)
		}
	}

	// Timestamp as 8-byte big-endian
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(r.Timestamp.Unix()))
	buf = append(buf, timestampBytes...)

	return buf
}

// Sign signs the request with the given Ed25519 private key.
func (r *DealBreakerRequest) Sign(privateKey ed25519.PrivateKey) error {
	r.Signature = ed25519.Sign(privateKey, r.BytesToSign())
	return nil
}

// Verify verifies the request signature using the given Ed25519 public key.
func (r *DealBreakerRequest) Verify(publicKey ed25519.PublicKey) error {
	if len(r.Signature) == 0 {
		return ErrSignatureRequired
	}

	if !ed25519.Verify(publicKey, r.BytesToSign(), r.Signature) {
		return ErrInvalidSignature
	}

	return nil
}

// NewDealBreakerResponse creates a new deal-breaker response with answers.
// The Matched field is computed by comparing myAnswers to peerQuestions' expected answers.
func NewDealBreakerResponse(peerID peer.ID, myAnswers [3]bool, peerQuestions [3]DealBreaker) *DealBreakerResponse {
	matched := CheckMatch(peerQuestions, myAnswers)

	return &DealBreakerResponse{
		PeerID:    peerID,
		Answers:   myAnswers,
		Matched:   matched,
		Timestamp: time.Now().UTC(),
	}
}

// BytesToSign returns the bytes that should be signed for this response.
// This includes peerID, answers, matched, and timestamp but NOT the signature.
func (r *DealBreakerResponse) BytesToSign() []byte {
	var buf []byte

	// PeerID
	buf = append(buf, []byte(r.PeerID)...)
	buf = append(buf, 0) // separator

	// Answers
	for i := 0; i < 3; i++ {
		if r.Answers[i] {
			buf = append(buf, 1)
		} else {
			buf = append(buf, 0)
		}
	}

	// Matched
	if r.Matched {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	// Timestamp as 8-byte big-endian
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(r.Timestamp.Unix()))
	buf = append(buf, timestampBytes...)

	return buf
}

// Sign signs the response with the given Ed25519 private key.
func (r *DealBreakerResponse) Sign(privateKey ed25519.PrivateKey) error {
	r.Signature = ed25519.Sign(privateKey, r.BytesToSign())
	return nil
}

// Verify verifies the response signature using the given Ed25519 public key.
func (r *DealBreakerResponse) Verify(publicKey ed25519.PublicKey) error {
	if len(r.Signature) == 0 {
		return ErrSignatureRequired
	}

	if !ed25519.Verify(publicKey, r.BytesToSign(), r.Signature) {
		return ErrInvalidSignature
	}

	return nil
}

// CheckMatch verifies that all peer answers match the expected answers in my questions.
// All 3 answers must match for this to return true.
func CheckMatch(myQuestions [3]DealBreaker, peerAnswers [3]bool) bool {
	for i := 0; i < 3; i++ {
		if myQuestions[i].Answer != peerAnswers[i] {
			return false
		}
	}
	return true
}

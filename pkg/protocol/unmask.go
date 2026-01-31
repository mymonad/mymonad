// Package protocol implements the MyMonad handshake protocol for agent matching.
package protocol

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"sort"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// Unmask errors.
var (
	// ErrUnmaskEmptyName is returned when the identity name is empty.
	ErrUnmaskEmptyName = errors.New("unmask: name cannot be empty")

	// ErrUnmaskEmptyContact is returned when the identity contact is empty.
	ErrUnmaskEmptyContact = errors.New("unmask: contact cannot be empty")

	// ErrUnmaskInvalidPublicKey is returned when the public key is invalid.
	ErrUnmaskInvalidPublicKey = errors.New("unmask: invalid public key")
)

// RealIdentity contains the real identity information that is exchanged
// when both parties approve unmasking. This is sensitive information
// and should only be revealed after mutual approval.
type RealIdentity struct {
	// Name is the real name of the person.
	Name string

	// Contact is the primary contact method (email, phone, etc.).
	Contact string

	// PublicKey is the Ed25519 public key for verification.
	PublicKey []byte

	// Extra contains optional additional fields.
	Extra map[string]string
}

// NewRealIdentity creates a new RealIdentity with the given required fields.
// The Extra map is initialized to an empty map.
func NewRealIdentity(name, contact string, publicKey ed25519.PublicKey) *RealIdentity {
	return &RealIdentity{
		Name:      name,
		Contact:   contact,
		PublicKey: publicKey,
		Extra:     make(map[string]string),
	}
}

// AddExtra adds an extra field to the identity.
func (id *RealIdentity) AddExtra(key, value string) {
	if id.Extra == nil {
		id.Extra = make(map[string]string)
	}
	id.Extra[key] = value
}

// Validate checks that the identity contains all required fields.
func (id *RealIdentity) Validate() error {
	if id.Name == "" {
		return ErrUnmaskEmptyName
	}
	if id.Contact == "" {
		return ErrUnmaskEmptyContact
	}
	if len(id.PublicKey) != ed25519.PublicKeySize {
		return ErrUnmaskInvalidPublicKey
	}
	return nil
}

// Clone creates a deep copy of the identity.
func (id *RealIdentity) Clone() *RealIdentity {
	clone := &RealIdentity{
		Name:    id.Name,
		Contact: id.Contact,
	}

	// Deep copy public key
	if id.PublicKey != nil {
		clone.PublicKey = make([]byte, len(id.PublicKey))
		copy(clone.PublicKey, id.PublicKey)
	}

	// Deep copy extra map
	clone.Extra = make(map[string]string, len(id.Extra))
	for k, v := range id.Extra {
		clone.Extra[k] = v
	}

	return clone
}

// bytesToSign returns the bytes that should be signed for this identity.
// This is used when including the identity in a response signature.
func (id *RealIdentity) bytesToSign() []byte {
	if id == nil {
		return nil
	}

	var buf []byte
	buf = append(buf, []byte(id.Name)...)
	buf = append(buf, 0) // separator
	buf = append(buf, []byte(id.Contact)...)
	buf = append(buf, 0) // separator
	buf = append(buf, id.PublicKey...)

	// Include extra fields in deterministic (sorted) order
	if len(id.Extra) > 0 {
		keys := make([]string, 0, len(id.Extra))
		for k := range id.Extra {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			buf = append(buf, 0) // separator
			buf = append(buf, []byte(k)...)
			buf = append(buf, '=')
			buf = append(buf, []byte(id.Extra[k])...)
		}
	}

	return buf
}

// UnmaskRequest represents a request sent during the unmask stage.
// The sender indicates whether they approve unmasking.
type UnmaskRequest struct {
	// PeerID is the sender's libp2p peer ID.
	PeerID peer.ID

	// Approved indicates whether the sender approves unmasking.
	Approved bool

	// Timestamp is when the request was created.
	Timestamp time.Time

	// Signature is the Ed25519 signature over the request content.
	Signature []byte
}

// NewUnmaskRequest creates a new unmask request.
func NewUnmaskRequest(peerID peer.ID, approved bool) *UnmaskRequest {
	return &UnmaskRequest{
		PeerID:    peerID,
		Approved:  approved,
		Timestamp: time.Now().UTC(),
	}
}

// BytesToSign returns the bytes that should be signed for this request.
// This includes peerID, approved flag, and timestamp but NOT the signature.
func (r *UnmaskRequest) BytesToSign() []byte {
	var buf []byte

	buf = append(buf, []byte(r.PeerID)...)
	buf = append(buf, 0) // separator

	// Approved as single byte
	if r.Approved {
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

// Sign signs the request with the given Ed25519 private key.
func (r *UnmaskRequest) Sign(privateKey ed25519.PrivateKey) error {
	r.Signature = ed25519.Sign(privateKey, r.BytesToSign())
	return nil
}

// Verify verifies the request signature using the given Ed25519 public key.
func (r *UnmaskRequest) Verify(publicKey ed25519.PublicKey) error {
	if len(r.Signature) == 0 {
		return ErrSignatureRequired
	}

	if !ed25519.Verify(publicKey, r.BytesToSign(), r.Signature) {
		return ErrInvalidSignature
	}

	return nil
}

// UnmaskResponse represents a response to an unmask request.
// If both parties approve, the response includes the real identity.
type UnmaskResponse struct {
	// PeerID is the responder's libp2p peer ID.
	PeerID peer.ID

	// Approved indicates whether the responder approves unmasking.
	Approved bool

	// Identity contains the real identity information.
	// This is only set if Approved is true.
	Identity *RealIdentity

	// Timestamp is when the response was created.
	Timestamp time.Time

	// Signature is the Ed25519 signature over the response content.
	Signature []byte
}

// NewUnmaskResponse creates a new unmask response.
// If approved is false, identity is set to nil regardless of what is passed.
// This ensures identity is never revealed when not approved.
func NewUnmaskResponse(peerID peer.ID, approved bool, identity *RealIdentity) *UnmaskResponse {
	resp := &UnmaskResponse{
		PeerID:    peerID,
		Approved:  approved,
		Timestamp: time.Now().UTC(),
	}

	// Only include identity if approved
	if approved && identity != nil {
		resp.Identity = identity
	}

	return resp
}

// BytesToSign returns the bytes that should be signed for this response.
// This includes peerID, approved flag, identity (if present), and timestamp
// but NOT the signature.
func (r *UnmaskResponse) BytesToSign() []byte {
	var buf []byte

	buf = append(buf, []byte(r.PeerID)...)
	buf = append(buf, 0) // separator

	// Approved as single byte
	if r.Approved {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	// Include identity bytes if present
	if r.Identity != nil {
		buf = append(buf, 0) // separator
		buf = append(buf, r.Identity.bytesToSign()...)
	}

	// Timestamp as 8-byte big-endian
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(r.Timestamp.Unix()))
	buf = append(buf, timestampBytes...)

	return buf
}

// Sign signs the response with the given Ed25519 private key.
func (r *UnmaskResponse) Sign(privateKey ed25519.PrivateKey) error {
	r.Signature = ed25519.Sign(privateKey, r.BytesToSign())
	return nil
}

// Verify verifies the response signature using the given Ed25519 public key.
func (r *UnmaskResponse) Verify(publicKey ed25519.PublicKey) error {
	if len(r.Signature) == 0 {
		return ErrSignatureRequired
	}

	if !ed25519.Verify(publicKey, r.BytesToSign(), r.Signature) {
		return ErrInvalidSignature
	}

	return nil
}

// CheckMutualApproval checks if both parties have approved unmasking.
// Returns true only if both the request and response have Approved=true.
// Returns false if either is nil or has Approved=false.
func CheckMutualApproval(request *UnmaskRequest, response *UnmaskResponse) bool {
	if request == nil || response == nil {
		return false
	}
	return request.Approved && response.Approved
}

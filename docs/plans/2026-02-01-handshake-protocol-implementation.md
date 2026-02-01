# Handshake Protocol Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire the existing protocol state machine to libp2p streams with automated peer matching and CLI control.

**Architecture:** Session Manager coordinates handshakes, libp2p streams carry protobuf messages, gRPC exposes control to CLI. Pull-based approval model with no hard timeouts.

**Tech Stack:** Go 1.21+, libp2p, protobuf, gRPC, go-bip39

---

## Task 1: Add BIP-39 Dependency and Mnemonic Identity

**Files:**
- Modify: `go.mod`
- Create: `internal/crypto/mnemonic.go`
- Create: `internal/crypto/mnemonic_test.go`

**Step 1: Write the failing test**

```go
// internal/crypto/mnemonic_test.go
package crypto

import (
	"testing"

	"github.com/tyler-smith/go-bip39"
)

func TestNewIdentityWithMnemonic(t *testing.T) {
	identity, mnemonic, err := NewIdentityWithMnemonic()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mnemonic should be 24 words
	words := strings.Split(mnemonic, " ")
	if len(words) != 24 {
		t.Errorf("expected 24 words, got %d", len(words))
	}

	// Mnemonic should be valid
	if !bip39.IsMnemonicValid(mnemonic) {
		t.Error("mnemonic is not valid")
	}

	// Identity should be non-nil
	if identity == nil {
		t.Fatal("identity is nil")
	}

	if identity.PrivateKey == nil {
		t.Error("private key is nil")
	}

	if identity.DID == "" {
		t.Error("DID is empty")
	}
}

func TestGenerateIdentityFromMnemonic_Deterministic(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	id1, err := GenerateIdentityFromMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	id2, err := GenerateIdentityFromMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Same mnemonic should produce same identity
	if id1.DID != id2.DID {
		t.Errorf("DIDs don't match: %s vs %s", id1.DID, id2.DID)
	}
}

func TestGenerateIdentityFromMnemonic_InvalidMnemonic(t *testing.T) {
	_, err := GenerateIdentityFromMnemonic("invalid mnemonic words")
	if err == nil {
		t.Error("expected error for invalid mnemonic")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v ./internal/crypto/... -run TestNewIdentityWithMnemonic`
Expected: FAIL - undefined: NewIdentityWithMnemonic

**Step 3: Add dependency**

Run: `go get github.com/tyler-smith/go-bip39`

**Step 4: Write minimal implementation**

```go
// internal/crypto/mnemonic.go
package crypto

import (
	"crypto/ed25519"
	"errors"

	"github.com/tyler-smith/go-bip39"
)

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

	return &Identity{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		DID:        deriveDID(publicKey),
	}, nil
}
```

**Step 5: Run tests to verify they pass**

Run: `go test -v ./internal/crypto/... -run Mnemonic`
Expected: PASS

**Step 6: Commit**

```bash
git add go.mod go.sum internal/crypto/mnemonic.go internal/crypto/mnemonic_test.go
git commit -m "feat(crypto): add BIP-39 mnemonic identity generation for recovery"
```

---

## Task 2: Add Temporal Decay to Monad

**Files:**
- Modify: `pkg/monad/monad.go`
- Modify: `pkg/monad/monad_test.go`

**Step 1: Write the failing test**

```go
// Add to pkg/monad/monad_test.go

func TestUpdateWithDecay(t *testing.T) {
	m := New(3)

	// First update - no decay (fresh monad)
	err := m.UpdateWithDecay([]float32{1.0, 0.0, 0.0}, 0.01)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if m.GetDocCount() != 1 {
		t.Errorf("expected doc count 1, got %d", m.GetDocCount())
	}

	// Vector should be approximately [1, 0, 0]
	if m.Vector[0] < 0.9 {
		t.Errorf("expected Vector[0] near 1.0, got %f", m.Vector[0])
	}
}

func TestUpdateWithDecay_OldDataDecays(t *testing.T) {
	m := New(3)

	// Simulate old data by setting UpdatedAt in the past
	m.Vector = []float32{1.0, 0.0, 0.0}
	m.DocCount = 1
	m.UpdatedAt = time.Now().Add(-70 * 24 * time.Hour) // 70 days ago

	// Update with lambda=0.01 (half-life ~70 days)
	// Old vector should decay by ~50%
	err := m.UpdateWithDecay([]float32{0.0, 1.0, 0.0}, 0.01)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Old component should be decayed
	if m.Vector[0] > 0.6 {
		t.Errorf("expected Vector[0] to decay below 0.6, got %f", m.Vector[0])
	}

	// New component should have weight
	if m.Vector[1] < 0.3 {
		t.Errorf("expected Vector[1] above 0.3, got %f", m.Vector[1])
	}
}

func TestUpdateWithDecay_DimensionMismatch(t *testing.T) {
	m := New(3)
	err := m.UpdateWithDecay([]float32{1.0, 2.0}, 0.01) // Wrong dimension
	if err != ErrDimensionMismatch {
		t.Errorf("expected ErrDimensionMismatch, got %v", err)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v ./pkg/monad/... -run TestUpdateWithDecay`
Expected: FAIL - undefined: UpdateWithDecay

**Step 3: Write minimal implementation**

```go
// Add to pkg/monad/monad.go

// UpdateWithDecay incorporates a new document embedding with temporal decay.
// The lambda parameter controls decay rate (0.01 ≈ 70-day half-life).
// Recent documents contribute more than older ones.
//
// Formula: existing_vector *= exp(-lambda * days_elapsed)
// Then applies running average with new embedding.
func (m *Monad) UpdateWithDecay(docEmbedding []float32, lambda float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(docEmbedding) != len(m.Vector) {
		return ErrDimensionMismatch
	}

	now := time.Now()

	// Apply decay to existing vector if we have prior data
	if m.DocCount > 0 {
		elapsed := now.Sub(m.UpdatedAt).Hours() / 24.0 // days
		decayFactor := float32(math.Exp(-lambda * elapsed))

		for i := range m.Vector {
			m.Vector[i] *= decayFactor
		}
	}

	// Running average update
	m.DocCount++
	weight := 1.0 / float32(m.DocCount)

	for i := range m.Vector {
		m.Vector[i] = m.Vector[i]*(1-weight) + docEmbedding[i]*weight
	}

	m.Version++
	m.UpdatedAt = now
	return nil
}
```

**Step 4: Add math import if needed**

Ensure `"math"` is in the imports of `pkg/monad/monad.go`.

**Step 5: Run tests to verify they pass**

Run: `go test -v ./pkg/monad/... -run TestUpdateWithDecay`
Expected: PASS

**Step 6: Commit**

```bash
git add pkg/monad/monad.go pkg/monad/monad_test.go
git commit -m "feat(monad): add temporal decay for dynamic affinity modeling"
```

---

## Task 3: Add Source Weighting to Embed Processor

**Files:**
- Create: `internal/embed/weights.go`
- Create: `internal/embed/weights_test.go`
- Modify: `internal/embed/processor.go`

**Step 1: Write the failing test**

```go
// internal/embed/weights_test.go
package embed

import "testing"

func TestGetWeight(t *testing.T) {
	tests := []struct {
		path     string
		expected float32
	}{
		{"/home/user/mail/important.eml", 3.0},
		{"/home/user/personal/diary.md", 2.5},
		{"/home/user/notes.md", 2.0},
		{"/home/user/random.txt", 1.5},
		{"/home/user/.bash_history", 0.3},
		{"/home/user/.zsh_history", 0.3},
		{"/home/user/unknown.xyz", 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			weight := GetWeight(tt.path)
			if weight != tt.expected {
				t.Errorf("GetWeight(%q) = %f, want %f", tt.path, weight, tt.expected)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v ./internal/embed/... -run TestGetWeight`
Expected: FAIL - undefined: GetWeight

**Step 3: Write minimal implementation**

```go
// internal/embed/weights.go
package embed

import (
	"path/filepath"
	"strings"
)

// SourceWeight defines a weight multiplier for files matching a pattern.
type SourceWeight struct {
	Pattern    string
	Multiplier float32
}

// DefaultWeights defines the default source weighting rules.
// Higher multiplier = more contribution to the monad.
// Order matters - first match wins.
var DefaultWeights = []SourceWeight{
	{"*.eml", 3.0},           // Email - high personal signal
	{"*/personal/*", 2.5},    // Personal folders
	{"*/diary/*", 2.5},       // Diary/journal
	{"*.md", 2.0},            // Long-form markdown
	{"*.txt", 1.5},           // Plain text notes
	{".bash_history", 0.3},   // Shell history - low signal
	{".zsh_history", 0.3},
	{".fish_history", 0.3},
	{"*", 1.0},               // Default
}

// GetWeight returns the weight multiplier for a file path.
// Uses DefaultWeights rules, first match wins.
func GetWeight(path string) float32 {
	return GetWeightWithRules(path, DefaultWeights)
}

// GetWeightWithRules returns the weight using custom rules.
func GetWeightWithRules(path string, rules []SourceWeight) float32 {
	filename := filepath.Base(path)

	for _, rule := range rules {
		// Check if pattern matches filename or path
		if matched, _ := filepath.Match(rule.Pattern, filename); matched {
			return rule.Multiplier
		}
		// Also check against full path for directory patterns
		if strings.Contains(rule.Pattern, "/") {
			if matched, _ := filepath.Match(rule.Pattern, path); matched {
				return rule.Multiplier
			}
			// Check if pattern substring exists in path
			patternPart := strings.Trim(rule.Pattern, "*")
			if strings.Contains(path, patternPart) {
				return rule.Multiplier
			}
		}
	}

	return 1.0 // Default weight
}
```

**Step 4: Run tests to verify they pass**

Run: `go test -v ./internal/embed/... -run TestGetWeight`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/embed/weights.go internal/embed/weights_test.go
git commit -m "feat(embed): add source weighting for semantic depth"
```

---

## Task 4: Create Handshake Protobuf Definitions

**Files:**
- Create: `api/proto/handshake.proto`
- Regenerate: `api/proto/handshake.pb.go`

**Step 1: Create protobuf file**

```protobuf
// api/proto/handshake.proto
syntax = "proto3";

package handshake;

option go_package = "github.com/mymonad/mymonad/api/proto";

// HandshakeEnvelope wraps all handshake messages.
message HandshakeEnvelope {
  MessageType type = 1;
  bytes payload = 2;
  int64 timestamp = 3;
  bytes signature = 4;
}

enum MessageType {
  ATTESTATION_REQUEST = 0;
  ATTESTATION_RESPONSE = 1;
  VECTOR_MATCH_REQUEST = 2;
  VECTOR_MATCH_RESPONSE = 3;
  DEALBREAKER_REQUEST = 4;
  DEALBREAKER_RESPONSE = 5;
  CHAT_MESSAGE = 6;
  UNMASK_REQUEST = 7;
  UNMASK_RESPONSE = 8;
  REJECT = 9;
}

// AttestationRequestPayload is the payload for ATTESTATION_REQUEST.
message AttestationRequestPayload {
  string version = 1;
  string peer_id = 2;
  string challenge = 3;  // Hashcash challenge
}

// AttestationResponsePayload is the payload for ATTESTATION_RESPONSE.
message AttestationResponsePayload {
  string version = 1;
  string peer_id = 2;
  string solution = 3;  // Hashcash solution
}

// VectorMatchRequestPayload is the payload for VECTOR_MATCH_REQUEST.
message VectorMatchRequestPayload {
  string peer_id = 1;
  bytes encrypted_monad = 2;
}

// VectorMatchResponsePayload is the payload for VECTOR_MATCH_RESPONSE.
message VectorMatchResponsePayload {
  string peer_id = 1;
  bool matched = 2;  // Score >= threshold (score not revealed)
}

// DealBreakerRequestPayload is the payload for DEALBREAKER_REQUEST.
message DealBreakerRequestPayload {
  repeated DealBreakerQuestion questions = 1;
}

message DealBreakerQuestion {
  string id = 1;
  string question = 2;
  bool answer = 3;  // Our answer
}

// DealBreakerResponsePayload is the payload for DEALBREAKER_RESPONSE.
message DealBreakerResponsePayload {
  repeated DealBreakerAnswer answers = 1;
  bool compatible = 2;
}

message DealBreakerAnswer {
  string question_id = 1;
  bool answer = 2;
}

// ChatMessagePayload is the payload for CHAT_MESSAGE.
message ChatMessagePayload {
  string message_id = 1;
  bytes encrypted_content = 2;  // Encrypted with session key
  int64 sequence = 3;
}

// UnmaskRequestPayload is the payload for UNMASK_REQUEST.
message UnmaskRequestPayload {
  bool ready = 1;  // Indicates ready to unmask
}

// UnmaskResponsePayload is the payload for UNMASK_RESPONSE.
message UnmaskResponsePayload {
  bool accepted = 1;
  IdentityPayload identity = 2;  // Only set if accepted
}

// IdentityPayload contains the revealed identity.
message IdentityPayload {
  string display_name = 1;

  // Contact method (at least one required)
  string email = 2;
  string signal_number = 3;
  string matrix_id = 4;

  // Optional verification
  bytes pgp_public_key = 5;
  string pgp_fingerprint = 6;

  // Proves contact belongs to this Ed25519 identity
  bytes contact_signature = 7;
}

// RejectPayload is the payload for REJECT.
message RejectPayload {
  string reason = 1;
  string stage = 2;  // Which stage the rejection occurred in
}
```

**Step 2: Generate Go code**

Run: `protoc --go_out=. --go_opt=paths=source_relative api/proto/handshake.proto`

**Step 3: Verify generation**

Run: `ls -la api/proto/handshake.pb.go`
Expected: File exists

**Step 4: Commit**

```bash
git add api/proto/handshake.proto api/proto/handshake.pb.go
git commit -m "feat(proto): add handshake protocol message definitions"
```

---

## Task 5: Extend AgentService gRPC with Handshake RPCs

**Files:**
- Modify: `api/proto/monad.proto`
- Regenerate: `api/proto/monad.pb.go`, `api/proto/monad_grpc.pb.go`

**Step 1: Add handshake RPCs to monad.proto**

Add after existing AgentService RPCs:

```protobuf
// Add to service AgentService in api/proto/monad.proto

  // Handshake operations
  rpc StartHandshake(StartHandshakeRequest) returns (StartHandshakeResponse);
  rpc ListHandshakes(ListHandshakesRequest) returns (ListHandshakesResponse);
  rpc GetHandshake(GetHandshakeRequest) returns (GetHandshakeResponse);
  rpc ApproveHandshake(ApproveHandshakeRequest) returns (ApproveHandshakeResponse);
  rpc RejectHandshake(RejectHandshakeRequest) returns (RejectHandshakeResponse);
  rpc WatchHandshakes(WatchHandshakesRequest) returns (stream HandshakeEvent);
```

Add message definitions:

```protobuf
// Handshake messages

message StartHandshakeRequest {
  string peer_id = 1;
}

message StartHandshakeResponse {
  string session_id = 1;
  string error = 2;
}

message ListHandshakesRequest {}

message ListHandshakesResponse {
  repeated HandshakeInfo handshakes = 1;
}

message GetHandshakeRequest {
  string session_id = 1;
}

message GetHandshakeResponse {
  HandshakeInfo handshake = 1;
  string error = 2;
}

message HandshakeInfo {
  string session_id = 1;
  string peer_id = 2;
  string state = 3;
  string role = 4;
  int64 elapsed_seconds = 5;
  bool pending_approval = 6;
  string pending_approval_type = 7;
}

message ApproveHandshakeRequest {
  string session_id = 1;
  IdentityPayload identity = 2;  // Required for unmask approval
}

message ApproveHandshakeResponse {
  bool success = 1;
  string error = 2;
}

message RejectHandshakeRequest {
  string session_id = 1;
  string reason = 2;
}

message RejectHandshakeResponse {
  bool success = 1;
  string error = 2;
}

message WatchHandshakesRequest {}

message HandshakeEvent {
  string session_id = 1;
  string event_type = 2;  // "started", "stage_changed", "pending_approval", "completed", "failed"
  string state = 3;
  string peer_id = 4;
  int64 elapsed_seconds = 5;
}

// Import IdentityPayload from handshake.proto or define inline
message IdentityPayload {
  string display_name = 1;
  string email = 2;
  string signal_number = 3;
  string matrix_id = 4;
  bytes pgp_public_key = 5;
  string pgp_fingerprint = 6;
  bytes contact_signature = 7;
}
```

**Step 2: Regenerate Go code**

Run: `protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative api/proto/monad.proto`

**Step 3: Verify build**

Run: `go build ./api/proto/...`
Expected: Success

**Step 4: Commit**

```bash
git add api/proto/monad.proto api/proto/monad.pb.go api/proto/monad_grpc.pb.go
git commit -m "feat(proto): add handshake gRPC operations to AgentService"
```

---

## Task 6: Create Session Type

**Files:**
- Create: `internal/handshake/session.go`
- Create: `internal/handshake/session_test.go`

**Step 1: Write the failing test**

```go
// internal/handshake/session_test.go
package handshake

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mymonad/mymonad/pkg/protocol"
)

func TestNewSession(t *testing.T) {
	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	s := NewSession(peerID, protocol.RoleInitiator, 0.85)

	if s.ID == "" {
		t.Error("session ID should not be empty")
	}

	if s.PeerID != peerID {
		t.Error("peer ID mismatch")
	}

	if s.Role != protocol.RoleInitiator {
		t.Error("role mismatch")
	}

	if s.Handshake == nil {
		t.Error("handshake should not be nil")
	}

	if s.Handshake.State() != protocol.StateIdle {
		t.Errorf("expected StateIdle, got %s", s.Handshake.State())
	}
}

func TestSession_Cleanup(t *testing.T) {
	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	s := NewSession(peerID, protocol.RoleInitiator, 0.85)

	// Set some sensitive data
	s.LocalMonad = []byte{1, 2, 3, 4, 5}
	s.PeerMonad = []byte{6, 7, 8, 9, 10}

	s.Cleanup()

	// Verify data is zeroed
	if s.LocalMonad != nil {
		t.Error("LocalMonad should be nil after cleanup")
	}
	if s.PeerMonad != nil {
		t.Error("PeerMonad should be nil after cleanup")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v ./internal/handshake/... -run TestNewSession`
Expected: FAIL - package not found

**Step 3: Write minimal implementation**

```go
// internal/handshake/session.go
package handshake

import (
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mymonad/mymonad/pkg/protocol"
)

// Session represents an active handshake with a peer.
type Session struct {
	mu sync.RWMutex

	ID           string
	PeerID       peer.ID
	Role         protocol.Role
	Handshake    *protocol.Handshake
	Stream       network.Stream
	StartedAt    time.Time
	LastActivity time.Time

	// Sensitive data - zeroed on cleanup
	LocalMonad []byte
	PeerMonad  []byte

	// Approval state
	PendingApproval     bool
	PendingApprovalType string
	PendingAt           time.Time
}

// NewSession creates a new handshake session.
func NewSession(peerID peer.ID, role protocol.Role, threshold float32) *Session {
	now := time.Now()
	return &Session{
		ID:           uuid.New().String(),
		PeerID:       peerID,
		Role:         role,
		Handshake:    protocol.NewHandshake(role, peerID, threshold),
		StartedAt:    now,
		LastActivity: now,
	}
}

// Cleanup zeroes sensitive data and releases resources.
// Must be called when session is complete or failed.
func (s *Session) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Zero sensitive byte slices
	for i := range s.LocalMonad {
		s.LocalMonad[i] = 0
	}
	s.LocalMonad = nil

	for i := range s.PeerMonad {
		s.PeerMonad[i] = 0
	}
	s.PeerMonad = nil

	// Close stream if open
	if s.Stream != nil {
		s.Stream.Close()
		s.Stream = nil
	}
}

// State returns the current handshake state.
func (s *Session) State() protocol.State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Handshake.State()
}

// ElapsedSeconds returns how long the session has been running.
func (s *Session) ElapsedSeconds() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(time.Since(s.StartedAt).Seconds())
}

// SetPendingApproval marks the session as waiting for human approval.
func (s *Session) SetPendingApproval(approvalType string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PendingApproval = true
	s.PendingApprovalType = approvalType
	s.PendingAt = time.Now()
}

// ClearPendingApproval clears the pending approval state.
func (s *Session) ClearPendingApproval() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PendingApproval = false
	s.PendingApprovalType = ""
}

// UpdateActivity updates the last activity timestamp.
func (s *Session) UpdateActivity() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastActivity = time.Now()
}
```

**Step 4: Add uuid dependency**

Run: `go get github.com/google/uuid`

**Step 5: Run tests to verify they pass**

Run: `go test -v ./internal/handshake/... -run TestNewSession`
Run: `go test -v ./internal/handshake/... -run TestSession_Cleanup`
Expected: PASS

**Step 6: Commit**

```bash
git add go.mod go.sum internal/handshake/session.go internal/handshake/session_test.go
git commit -m "feat(handshake): add Session type with secure cleanup"
```

---

## Task 7: Create Session Manager

**Files:**
- Create: `internal/handshake/manager.go`
- Create: `internal/handshake/manager_test.go`

**Step 1: Write the failing test**

```go
// internal/handshake/manager_test.go
package handshake

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestNewManager(t *testing.T) {
	cfg := ManagerConfig{
		AutoInitiate:     true,
		CooldownDuration: 1 * time.Hour,
		Threshold:        0.85,
	}

	m := NewManager(nil, cfg) // nil host for unit test

	if m == nil {
		t.Fatal("manager should not be nil")
	}

	if !m.cfg.AutoInitiate {
		t.Error("auto initiate should be true")
	}
}

func TestManager_CanInitiate(t *testing.T) {
	cfg := ManagerConfig{
		CooldownDuration: 1 * time.Hour,
		Threshold:        0.85,
	}
	m := NewManager(nil, cfg)

	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Should be able to initiate to new peer
	if !m.CanInitiate(peerID) {
		t.Error("should be able to initiate to new peer")
	}

	// Record an attempt
	m.RecordAttempt(peerID)

	// Should not be able to initiate again (cooldown)
	if m.CanInitiate(peerID) {
		t.Error("should not be able to initiate during cooldown")
	}
}

func TestManager_AddRemoveSession(t *testing.T) {
	cfg := ManagerConfig{
		CooldownDuration: 1 * time.Hour,
		Threshold:        0.85,
	}
	m := NewManager(nil, cfg)

	peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	// Add session
	s := m.CreateSession(peerID, protocol.RoleInitiator)
	if s == nil {
		t.Fatal("session should not be nil")
	}

	// Should find session
	found := m.GetSession(s.ID)
	if found == nil {
		t.Error("should find session by ID")
	}

	// Remove session
	m.RemoveSession(s.ID)

	// Should not find session
	found = m.GetSession(s.ID)
	if found != nil {
		t.Error("should not find removed session")
	}

	// PeerHistory should be updated
	if m.CanInitiate(peerID) {
		t.Error("should not be able to initiate after session removal (cooldown)")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v ./internal/handshake/... -run TestNewManager`
Expected: FAIL - undefined: NewManager

**Step 3: Write minimal implementation**

```go
// internal/handshake/manager.go
package handshake

import (
	"context"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mymonad/mymonad/pkg/protocol"
)

// ManagerConfig holds configuration for the handshake manager.
type ManagerConfig struct {
	AutoInitiate     bool
	CooldownDuration time.Duration
	Threshold        float32
}

// Manager coordinates handshake sessions.
type Manager struct {
	mu          sync.RWMutex
	host        host.Host
	cfg         ManagerConfig
	sessions    map[string]*Session
	peerHistory map[peer.ID]time.Time

	// Event subscribers
	eventsMu    sync.RWMutex
	subscribers []chan Event
}

// Event represents a handshake event for subscribers.
type Event struct {
	SessionID      string
	EventType      string // "started", "stage_changed", "pending_approval", "completed", "failed"
	State          string
	PeerID         string
	ElapsedSeconds int64
}

// NewManager creates a new handshake manager.
func NewManager(h host.Host, cfg ManagerConfig) *Manager {
	return &Manager{
		host:        h,
		cfg:         cfg,
		sessions:    make(map[string]*Session),
		peerHistory: make(map[peer.ID]time.Time),
	}
}

// CanInitiate checks if we can start a handshake with the peer.
func (m *Manager) CanInitiate(peerID peer.ID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check for active session
	for _, s := range m.sessions {
		if s.PeerID == peerID && !s.Handshake.IsTerminal() {
			return false
		}
	}

	// Check cooldown
	if lastAttempt, ok := m.peerHistory[peerID]; ok {
		if time.Since(lastAttempt) < m.cfg.CooldownDuration {
			return false
		}
	}

	return true
}

// RecordAttempt records a handshake attempt time for a peer.
func (m *Manager) RecordAttempt(peerID peer.ID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerHistory[peerID] = time.Now()
}

// CreateSession creates a new session for a peer.
func (m *Manager) CreateSession(peerID peer.ID, role protocol.Role) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()

	s := NewSession(peerID, role, m.cfg.Threshold)
	m.sessions[s.ID] = s
	m.peerHistory[peerID] = time.Now()

	return s
}

// GetSession returns a session by ID.
func (m *Manager) GetSession(id string) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id]
}

// GetSessionByPeer returns an active session with a peer.
func (m *Manager) GetSessionByPeer(peerID peer.ID) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, s := range m.sessions {
		if s.PeerID == peerID && !s.Handshake.IsTerminal() {
			return s
		}
	}
	return nil
}

// RemoveSession removes a session and updates peer history.
func (m *Manager) RemoveSession(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.sessions[id]; ok {
		// Update peer history BEFORE removing
		m.peerHistory[s.PeerID] = time.Now()
		s.Cleanup()
		delete(m.sessions, id)
	}
}

// ListSessions returns all sessions.
func (m *Manager) ListSessions() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		result = append(result, s)
	}
	return result
}

// Subscribe returns a channel that receives handshake events.
func (m *Manager) Subscribe() <-chan Event {
	m.eventsMu.Lock()
	defer m.eventsMu.Unlock()

	ch := make(chan Event, 100)
	m.subscribers = append(m.subscribers, ch)
	return ch
}

// Unsubscribe removes an event subscription.
func (m *Manager) Unsubscribe(ch <-chan Event) {
	m.eventsMu.Lock()
	defer m.eventsMu.Unlock()

	for i, sub := range m.subscribers {
		if sub == ch {
			close(sub)
			m.subscribers = append(m.subscribers[:i], m.subscribers[i+1:]...)
			return
		}
	}
}

// EmitEvent sends an event to all subscribers.
func (m *Manager) EmitEvent(e Event) {
	m.eventsMu.RLock()
	defer m.eventsMu.RUnlock()

	for _, ch := range m.subscribers {
		select {
		case ch <- e:
		default:
			// Channel full, skip
		}
	}
}

// CleanupLoop periodically removes stale sessions.
func (m *Manager) CleanupLoop(ctx context.Context, staleAfter time.Duration) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			for id, s := range m.sessions {
				if s.Handshake.IsTerminal() && time.Since(s.LastActivity) > staleAfter {
					m.peerHistory[s.PeerID] = time.Now()
					s.Cleanup()
					delete(m.sessions, id)
				}
			}
			m.mu.Unlock()
		}
	}
}
```

**Step 4: Run tests to verify they pass**

Run: `go test -v ./internal/handshake/...`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/handshake/manager.go internal/handshake/manager_test.go
git commit -m "feat(handshake): add session Manager with cooldown and cleanup"
```

---

## Task 8: Create Wire Codec for Stream Protocol

**Files:**
- Create: `internal/handshake/codec.go`
- Create: `internal/handshake/codec_test.go`

**Step 1: Write the failing test**

```go
// internal/handshake/codec_test.go
package handshake

import (
	"bytes"
	"testing"

	pb "github.com/mymonad/mymonad/api/proto"
)

func TestCodec_WriteReadEnvelope(t *testing.T) {
	var buf bytes.Buffer

	// Write envelope
	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_REQUEST,
		Payload:   []byte("test payload"),
		Timestamp: 1234567890,
		Signature: []byte("sig"),
	}

	err := WriteEnvelope(&buf, env)
	if err != nil {
		t.Fatalf("write error: %v", err)
	}

	// Read envelope back
	readEnv, err := ReadEnvelope(&buf)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}

	if readEnv.Type != env.Type {
		t.Errorf("type mismatch: got %v, want %v", readEnv.Type, env.Type)
	}

	if !bytes.Equal(readEnv.Payload, env.Payload) {
		t.Error("payload mismatch")
	}

	if readEnv.Timestamp != env.Timestamp {
		t.Error("timestamp mismatch")
	}
}

func TestCodec_MaxMessageSize(t *testing.T) {
	var buf bytes.Buffer

	// Create oversized payload
	env := &pb.HandshakeEnvelope{
		Type:    pb.MessageType_ATTESTATION_REQUEST,
		Payload: make([]byte, MaxMessageSize+1),
	}

	err := WriteEnvelope(&buf, env)
	if err == nil {
		t.Error("expected error for oversized message")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v ./internal/handshake/... -run TestCodec`
Expected: FAIL - undefined: WriteEnvelope

**Step 3: Write minimal implementation**

```go
// internal/handshake/codec.go
package handshake

import (
	"encoding/binary"
	"errors"
	"io"

	pb "github.com/mymonad/mymonad/api/proto"
	"google.golang.org/protobuf/proto"
)

const (
	// MaxMessageSize is the maximum allowed message size (1MB).
	MaxMessageSize = 1 << 20

	// LengthPrefixSize is the size of the length prefix (4 bytes).
	LengthPrefixSize = 4
)

var (
	ErrMessageTooLarge = errors.New("handshake: message exceeds maximum size")
	ErrInvalidLength   = errors.New("handshake: invalid message length")
)

// WriteEnvelope writes a length-prefixed protobuf envelope to the writer.
func WriteEnvelope(w io.Writer, env *pb.HandshakeEnvelope) error {
	data, err := proto.Marshal(env)
	if err != nil {
		return err
	}

	if len(data) > MaxMessageSize {
		return ErrMessageTooLarge
	}

	// Write length prefix (big-endian uint32)
	lengthBuf := make([]byte, LengthPrefixSize)
	binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))

	if _, err := w.Write(lengthBuf); err != nil {
		return err
	}

	if _, err := w.Write(data); err != nil {
		return err
	}

	return nil
}

// ReadEnvelope reads a length-prefixed protobuf envelope from the reader.
func ReadEnvelope(r io.Reader) (*pb.HandshakeEnvelope, error) {
	// Read length prefix
	lengthBuf := make([]byte, LengthPrefixSize)
	if _, err := io.ReadFull(r, lengthBuf); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(lengthBuf)

	if length > MaxMessageSize {
		return nil, ErrMessageTooLarge
	}

	if length == 0 {
		return nil, ErrInvalidLength
	}

	// Read message data
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}

	// Unmarshal protobuf
	env := &pb.HandshakeEnvelope{}
	if err := proto.Unmarshal(data, env); err != nil {
		return nil, err
	}

	return env, nil
}
```

**Step 4: Run tests to verify they pass**

Run: `go test -v ./internal/handshake/... -run TestCodec`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/handshake/codec.go internal/handshake/codec_test.go
git commit -m "feat(handshake): add length-prefixed protobuf wire codec"
```

---

## Task 9: Create libp2p Stream Handler

**Files:**
- Create: `internal/handshake/stream.go`
- Create: `internal/handshake/stream_test.go`

**Step 1: Write the failing test**

```go
// internal/handshake/stream_test.go
package handshake

import (
	"testing"
)

func TestProtocolID(t *testing.T) {
	if ProtocolID != "/mymonad/handshake/1.0.0" {
		t.Errorf("unexpected protocol ID: %s", ProtocolID)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v ./internal/handshake/... -run TestProtocolID`
Expected: FAIL - undefined: ProtocolID

**Step 3: Write implementation**

```go
// internal/handshake/stream.go
package handshake

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	pb "github.com/mymonad/mymonad/api/proto"
	proto "github.com/mymonad/mymonad/pkg/protocol"
)

// ProtocolID is the libp2p protocol identifier for handshakes.
const ProtocolID = "/mymonad/handshake/1.0.0"

// StreamHandler handles incoming handshake streams.
type StreamHandler struct {
	manager *Manager
	logger  *slog.Logger
}

// NewStreamHandler creates a new stream handler.
func NewStreamHandler(manager *Manager, logger *slog.Logger) *StreamHandler {
	return &StreamHandler{
		manager: manager,
		logger:  logger,
	}
}

// Register registers the stream handler with the host.
func (h *StreamHandler) Register(host host.Host) {
	host.SetStreamHandler(protocol.ID(ProtocolID), h.handleStream)
}

// handleStream handles an incoming handshake stream.
func (h *StreamHandler) handleStream(s network.Stream) {
	peerID := s.Conn().RemotePeer()
	h.logger.Info("incoming handshake stream", "peer", peerID.String())

	// Check if we can accept this handshake
	if !h.manager.CanInitiate(peerID) {
		h.logger.Warn("rejecting handshake, cooldown active", "peer", peerID.String())
		h.sendReject(s, "cooldown active")
		s.Close()
		return
	}

	// Create session as responder
	session := h.manager.CreateSession(peerID, proto.RoleResponder)
	session.Stream = s

	h.manager.EmitEvent(Event{
		SessionID: session.ID,
		EventType: "started",
		State:     session.State().String(),
		PeerID:    peerID.String(),
	})

	// Start the protocol handler
	go h.runProtocol(session)
}

// InitiateHandshake starts a handshake with a peer.
func (h *StreamHandler) InitiateHandshake(ctx context.Context, host host.Host, peerID peer.ID) (*Session, error) {
	// Check cooldown
	if !h.manager.CanInitiate(peerID) {
		return nil, fmt.Errorf("cooldown active for peer %s", peerID.String())
	}

	// Open stream
	s, err := host.NewStream(ctx, peerID, protocol.ID(ProtocolID))
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}

	// Create session as initiator
	session := h.manager.CreateSession(peerID, proto.RoleInitiator)
	session.Stream = s

	h.manager.EmitEvent(Event{
		SessionID: session.ID,
		EventType: "started",
		State:     session.State().String(),
		PeerID:    peerID.String(),
	})

	// Start the protocol handler
	go h.runProtocol(session)

	return session, nil
}

// runProtocol runs the handshake protocol for a session.
func (h *StreamHandler) runProtocol(session *Session) {
	defer func() {
		h.manager.RemoveSession(session.ID)
	}()

	// Start state machine
	if err := session.Handshake.Transition(proto.EventInitiate); err != nil {
		h.logger.Error("failed to start handshake", "error", err)
		return
	}

	h.emitStateChange(session)

	// Protocol loop based on role
	if session.Role == proto.RoleInitiator {
		h.runInitiator(session)
	} else {
		h.runResponder(session)
	}
}

// runInitiator runs the initiator side of the protocol.
func (h *StreamHandler) runInitiator(session *Session) {
	// Stage 1: Send attestation request
	h.logger.Info("sending attestation request", "session", session.ID)

	// TODO: Implement full protocol stages
	// For now, just a placeholder that will be expanded

	h.logger.Info("initiator protocol complete", "session", session.ID)
}

// runResponder runs the responder side of the protocol.
func (h *StreamHandler) runResponder(session *Session) {
	// Stage 1: Receive and respond to attestation
	h.logger.Info("waiting for attestation request", "session", session.ID)

	// TODO: Implement full protocol stages

	h.logger.Info("responder protocol complete", "session", session.ID)
}

// sendReject sends a reject message and closes the stream.
func (h *StreamHandler) sendReject(s network.Stream, reason string) {
	env := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_REJECT,
		Payload:   []byte(reason),
		Timestamp: time.Now().Unix(),
	}
	WriteEnvelope(s, env)
}

// emitStateChange emits a state change event.
func (h *StreamHandler) emitStateChange(session *Session) {
	h.manager.EmitEvent(Event{
		SessionID:      session.ID,
		EventType:      "stage_changed",
		State:          session.State().String(),
		PeerID:         session.PeerID.String(),
		ElapsedSeconds: session.ElapsedSeconds(),
	})
}
```

**Step 4: Run tests to verify they pass**

Run: `go test -v ./internal/handshake/... -run TestProtocolID`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/handshake/stream.go internal/handshake/stream_test.go
git commit -m "feat(handshake): add libp2p stream handler scaffold"
```

---

## Task 10: Add Handshake CLI Commands

**Files:**
- Modify: `cmd/mymonad-cli/commands.go`
- Modify: `cmd/mymonad-cli/main.go`

**Step 1: Add handshake subcommands to commands.go**

```go
// Add to cmd/mymonad-cli/commands.go

func handshakeCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mymonad-cli handshake <subcommand>")
	}

	subcommand := args[0]
	subargs := args[1:]

	switch subcommand {
	case "start":
		return handshakeStart(subargs)
	case "list":
		return handshakeList()
	case "show":
		return handshakeShow(subargs)
	case "approve":
		return handshakeApprove(subargs)
	case "reject":
		return handshakeReject(subargs)
	case "watch":
		return handshakeWatch()
	default:
		return fmt.Errorf("unknown handshake subcommand: %s", subcommand)
	}
}

func handshakeStart(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mymonad-cli handshake start <peer-id>")
	}
	peerID := args[0]

	conn, err := connectToAgent()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pb.NewAgentServiceClient(conn)
	resp, err := client.StartHandshake(context.Background(), &pb.StartHandshakeRequest{
		PeerId: peerID,
	})
	if err != nil {
		return fmt.Errorf("failed to start handshake: %w", err)
	}

	if resp.Error != "" {
		return fmt.Errorf("handshake error: %s", resp.Error)
	}

	fmt.Printf("Handshake started: session_id=%s\n", resp.SessionId)
	return nil
}

func handshakeList() error {
	conn, err := connectToAgent()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pb.NewAgentServiceClient(conn)
	resp, err := client.ListHandshakes(context.Background(), &pb.ListHandshakesRequest{})
	if err != nil {
		return fmt.Errorf("failed to list handshakes: %w", err)
	}

	if len(resp.Handshakes) == 0 {
		fmt.Println("No active handshakes")
		return nil
	}

	fmt.Printf("%-36s  %-12s  %-10s  %-8s  %s\n", "SESSION", "STATE", "ROLE", "ELAPSED", "PEER")
	for _, h := range resp.Handshakes {
		pending := ""
		if h.PendingApproval {
			pending = fmt.Sprintf(" [PENDING: %s]", h.PendingApprovalType)
		}
		fmt.Printf("%-36s  %-12s  %-10s  %-8ds  %s%s\n",
			h.SessionId, h.State, h.Role, h.ElapsedSeconds, h.PeerId[:16]+"...", pending)
	}

	return nil
}

func handshakeShow(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mymonad-cli handshake show <session-id>")
	}
	sessionID := args[0]

	conn, err := connectToAgent()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pb.NewAgentServiceClient(conn)
	resp, err := client.GetHandshake(context.Background(), &pb.GetHandshakeRequest{
		SessionId: sessionID,
	})
	if err != nil {
		return fmt.Errorf("failed to get handshake: %w", err)
	}

	if resp.Error != "" {
		return fmt.Errorf("error: %s", resp.Error)
	}

	h := resp.Handshake
	fmt.Printf("Session ID: %s\n", h.SessionId)
	fmt.Printf("Peer ID:    %s\n", h.PeerId)
	fmt.Printf("State:      %s\n", h.State)
	fmt.Printf("Role:       %s\n", h.Role)
	fmt.Printf("Elapsed:    %d seconds\n", h.ElapsedSeconds)
	if h.PendingApproval {
		fmt.Printf("Pending:    %s\n", h.PendingApprovalType)
	}

	return nil
}

func handshakeApprove(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mymonad-cli handshake approve <session-id>")
	}
	sessionID := args[0]

	conn, err := connectToAgent()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pb.NewAgentServiceClient(conn)
	resp, err := client.ApproveHandshake(context.Background(), &pb.ApproveHandshakeRequest{
		SessionId: sessionID,
	})
	if err != nil {
		return fmt.Errorf("failed to approve: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("approval failed: %s", resp.Error)
	}

	fmt.Println("Handshake approved")
	return nil
}

func handshakeReject(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mymonad-cli handshake reject <session-id> [reason]")
	}
	sessionID := args[0]
	reason := ""
	if len(args) > 1 {
		reason = args[1]
	}

	conn, err := connectToAgent()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pb.NewAgentServiceClient(conn)
	resp, err := client.RejectHandshake(context.Background(), &pb.RejectHandshakeRequest{
		SessionId: sessionID,
		Reason:    reason,
	})
	if err != nil {
		return fmt.Errorf("failed to reject: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("rejection failed: %s", resp.Error)
	}

	fmt.Println("Handshake rejected")
	return nil
}

func handshakeWatch() error {
	conn, err := connectToAgent()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pb.NewAgentServiceClient(conn)
	stream, err := client.WatchHandshakes(context.Background(), &pb.WatchHandshakesRequest{})
	if err != nil {
		return fmt.Errorf("failed to watch: %w", err)
	}

	fmt.Println("Watching handshake events (Ctrl+C to stop)...")

	for {
		event, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("stream error: %w", err)
		}

		fmt.Printf("[%s] session=%s peer=%s state=%s elapsed=%ds\n",
			event.EventType, event.SessionId[:8]+"...", event.PeerId[:16]+"...",
			event.State, event.ElapsedSeconds)
	}
}
```

**Step 2: Add handshake to main command dispatch**

In `cmd/mymonad-cli/main.go`, add "handshake" to the command switch.

**Step 3: Build and test**

Run: `go build ./cmd/mymonad-cli`
Run: `./bin/mymonad-cli handshake list`
Expected: "No active handshakes" or connection error (agent not running)

**Step 4: Commit**

```bash
git add cmd/mymonad-cli/commands.go cmd/mymonad-cli/main.go
git commit -m "feat(cli): add handshake subcommands (start, list, show, approve, reject, watch)"
```

---

## Task 11: Integrate Handshake Manager into Agent Daemon

**Files:**
- Modify: `cmd/mymonad-agent/daemon.go`

**Step 1: Add handshake manager to Daemon struct**

```go
// Add to Daemon struct
handshakeManager *handshake.Manager
handshakeHandler *handshake.StreamHandler
```

**Step 2: Initialize in NewDaemon**

```go
// In NewDaemon, after creating host:
handshakeMgr := handshake.NewManager(host.Host(), handshake.ManagerConfig{
    AutoInitiate:     true,
    CooldownDuration: 1 * time.Hour,
    Threshold:        float32(cfg.SimilarityThreshold),
})

handshakeHandler := handshake.NewStreamHandler(handshakeMgr, logger)
handshakeHandler.Register(host.Host())
```

**Step 3: Implement gRPC handlers**

Add implementations for StartHandshake, ListHandshakes, GetHandshake, ApproveHandshake, RejectHandshake, WatchHandshakes.

**Step 4: Start cleanup loop in Run**

```go
// In Run(), before the select:
go d.handshakeManager.CleanupLoop(ctx, 5*time.Minute)
```

**Step 5: Test integration**

Run: `go build ./cmd/mymonad-agent && ./bin/mymonad-agent`
Run: `./bin/mymonad-cli handshake list`
Expected: "No active handshakes"

**Step 6: Commit**

```bash
git add cmd/mymonad-agent/daemon.go
git commit -m "feat(agent): integrate handshake manager and gRPC handlers"
```

---

## Task 12: Implement Full Attestation Stage

**Files:**
- Modify: `internal/handshake/stream.go`

**Step 1: Implement attestation in runInitiator**

```go
func (h *StreamHandler) runInitiator(session *Session) {
    // Stage 1: Attestation
    if err := h.doAttestationInitiator(session); err != nil {
        h.logger.Error("attestation failed", "error", err)
        session.Handshake.Transition(proto.EventAttestationFailure)
        return
    }
    session.Handshake.Transition(proto.EventAttestationSuccess)
    h.emitStateChange(session)

    // Continue to next stages...
}

func (h *StreamHandler) doAttestationInitiator(session *Session) error {
    // Create challenge
    req, err := proto.NewAttestationRequest(h.manager.host.ID(), "1.0.0", 16)
    if err != nil {
        return err
    }

    // Serialize and send
    payload, _ := json.Marshal(req) // TODO: use protobuf
    env := &pb.HandshakeEnvelope{
        Type:      pb.MessageType_ATTESTATION_REQUEST,
        Payload:   payload,
        Timestamp: time.Now().Unix(),
    }
    if err := WriteEnvelope(session.Stream, env); err != nil {
        return err
    }

    // Read response
    respEnv, err := ReadEnvelope(session.Stream)
    if err != nil {
        return err
    }

    if respEnv.Type == pb.MessageType_REJECT {
        return fmt.Errorf("peer rejected: %s", string(respEnv.Payload))
    }

    // Verify PoW
    var resp proto.AttestationResponse
    json.Unmarshal(respEnv.Payload, &resp)
    if !resp.VerifyPoW(16) {
        return fmt.Errorf("invalid PoW")
    }

    return nil
}
```

**Step 2: Implement attestation in runResponder**

Similar pattern - receive request, solve PoW, send response.

**Step 3: Test with two local agents**

Run two agents on different ports, use CLI to initiate handshake.

**Step 4: Commit**

```bash
git add internal/handshake/stream.go
git commit -m "feat(handshake): implement attestation stage with hashcash PoW"
```

---

## Task 13: Implement Vector Match Stage

**Files:**
- Modify: `internal/handshake/stream.go`

Similar to Task 12, implement the vector match stage using MockTEE.

**Commit message:** `feat(handshake): implement vector match stage with MockTEE`

---

## Task 14: Implement Deal Breakers Stage

**Files:**
- Modify: `internal/handshake/stream.go`

Implement deal breaker question exchange.

**Commit message:** `feat(handshake): implement deal breakers stage`

---

## Task 15: Implement Unmask Stage with Approval

**Files:**
- Modify: `internal/handshake/stream.go`

Implement unmask with pending approval that waits for human input via CLI.

**Commit message:** `feat(handshake): implement unmask stage with async approval`

---

## Task 16: Integration Tests

**Files:**
- Create: `tests/handshake_integration_test.go`

Write end-to-end tests with two in-process agents completing a full handshake.

**Commit message:** `test(handshake): add integration tests for full protocol flow`

---

## Summary

| Task | Component | Commits |
|------|-----------|---------|
| 1 | BIP-39 Mnemonic | 1 |
| 2 | Temporal Decay | 1 |
| 3 | Source Weighting | 1 |
| 4 | Handshake Protobuf | 1 |
| 5 | gRPC Extensions | 1 |
| 6 | Session Type | 1 |
| 7 | Session Manager | 1 |
| 8 | Wire Codec | 1 |
| 9 | Stream Handler | 1 |
| 10 | CLI Commands | 1 |
| 11 | Agent Integration | 1 |
| 12-15 | Protocol Stages | 4 |
| 16 | Integration Tests | 1 |

**Total: 16 tasks, ~16 commits**

package discovery

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// ============================================================
// NewExchange Tests
// ============================================================

func TestNewExchange(t *testing.T) {
	peerID := peer.ID("test-peer")
	sig := makeSignature(32)

	ex, err := NewExchange(peerID, RoleInitiator, sig)
	if err != nil {
		t.Fatalf("NewExchange() error = %v", err)
	}
	if ex.PeerID != peerID {
		t.Errorf("PeerID = %v, want %v", ex.PeerID, peerID)
	}
	if ex.Role != RoleInitiator {
		t.Errorf("Role = %v, want %v", ex.Role, RoleInitiator)
	}
	if ex.State != ExchangeStatePending {
		t.Errorf("State = %v, want %v", ex.State, ExchangeStatePending)
	}
	if len(ex.SignatureSnapshot) != 32 {
		t.Errorf("SignatureSnapshot length = %d, want 32", len(ex.SignatureSnapshot))
	}
	if len(ex.Salt) != 16 {
		t.Errorf("Salt length = %d, want 16", len(ex.Salt))
	}
	if len(ex.Commitment) != 32 {
		t.Errorf("Commitment length = %d, want 32", len(ex.Commitment))
	}
	if ex.IsExpired() {
		t.Error("newly created exchange should not be expired")
	}
}

func TestNewExchange_ResponderRole(t *testing.T) {
	peerID := peer.ID("test-peer")
	sig := makeSignature(32)

	ex, err := NewExchange(peerID, RoleResponder, sig)
	if err != nil {
		t.Fatalf("NewExchange() error = %v", err)
	}
	if ex.Role != RoleResponder {
		t.Errorf("Role = %v, want %v", ex.Role, RoleResponder)
	}
}

func TestNewExchange_CommitmentMatchesSignatureAndSalt(t *testing.T) {
	sig := makeSignature(32)

	ex, err := NewExchange(peer.ID("test"), RoleInitiator, sig)
	if err != nil {
		t.Fatalf("NewExchange() error = %v", err)
	}

	// Verify commitment is correctly computed from signature snapshot and salt
	err = verifyCommitment(ex.Commitment, ex.SignatureSnapshot, ex.Salt)
	if err != nil {
		t.Errorf("commitment verification failed: %v", err)
	}
}

func TestNewExchange_TimingFields(t *testing.T) {
	before := time.Now()
	ex, err := NewExchange(peer.ID("test"), RoleInitiator, makeSignature(32))
	after := time.Now()

	if err != nil {
		t.Fatalf("NewExchange() error = %v", err)
	}

	// CreatedAt should be between before and after
	if ex.CreatedAt.Before(before) || ex.CreatedAt.After(after) {
		t.Errorf("CreatedAt = %v, should be between %v and %v", ex.CreatedAt, before, after)
	}

	// ExpiresAt should be CreatedAt + 30 seconds
	expectedExpiry := ex.CreatedAt.Add(ExchangeTimeout)
	if !ex.ExpiresAt.Equal(expectedExpiry) {
		t.Errorf("ExpiresAt = %v, want %v", ex.ExpiresAt, expectedExpiry)
	}
}

func TestNewExchange_RetryCountZero(t *testing.T) {
	ex, err := NewExchange(peer.ID("test"), RoleInitiator, makeSignature(32))
	if err != nil {
		t.Fatalf("NewExchange() error = %v", err)
	}

	if ex.RetryCount != 0 {
		t.Errorf("RetryCount = %d, want 0", ex.RetryCount)
	}
}

// ============================================================
// Signature Snapshot Immutability Tests
// ============================================================

func TestExchange_SignatureSnapshotImmutable(t *testing.T) {
	sig := makeSignature(32)
	originalSig := make([]byte, 32)
	copy(originalSig, sig)

	ex, err := NewExchange(peer.ID("test"), RoleInitiator, sig)
	if err != nil {
		t.Fatalf("NewExchange() error = %v", err)
	}

	// Modify original signature (simulating Monad update)
	sig[0] ^= 0xFF

	// Snapshot must remain unchanged
	for i := range originalSig {
		if ex.SignatureSnapshot[i] != originalSig[i] {
			t.Errorf("SignatureSnapshot[%d] = %d, want %d (original was modified)", i, ex.SignatureSnapshot[i], originalSig[i])
		}
	}

	// Commitment must still verify against snapshot
	err = verifyCommitment(ex.Commitment, ex.SignatureSnapshot, ex.Salt)
	if err != nil {
		t.Errorf("commitment verification should succeed with snapshot: %v", err)
	}
}

func TestExchange_SignatureSnapshotNotAffectedByExternalChanges(t *testing.T) {
	sig := makeSignature(32)

	ex, err := NewExchange(peer.ID("test"), RoleInitiator, sig)
	if err != nil {
		t.Fatalf("NewExchange() error = %v", err)
	}

	// Capture original snapshot
	originalSnapshot := make([]byte, len(ex.SignatureSnapshot))
	copy(originalSnapshot, ex.SignatureSnapshot)

	// Modify the original signature completely
	for i := range sig {
		sig[i] = byte(i)
	}

	// Snapshot should remain unchanged
	for i := range originalSnapshot {
		if ex.SignatureSnapshot[i] != originalSnapshot[i] {
			t.Errorf("SignatureSnapshot was modified after external change")
			break
		}
	}
}

// ============================================================
// IsExpired Tests
// ============================================================

func TestExchange_IsExpired_NotExpired(t *testing.T) {
	ex, _ := NewExchange(peer.ID("test"), RoleInitiator, makeSignature(32))

	if ex.IsExpired() {
		t.Error("exchange should not be expired immediately after creation")
	}
}

func TestExchange_IsExpired_AfterTimeout(t *testing.T) {
	ex, _ := NewExchange(peer.ID("test"), RoleInitiator, makeSignature(32))

	// Manually set expiry to the past
	ex.ExpiresAt = time.Now().Add(-time.Second)

	if !ex.IsExpired() {
		t.Error("exchange should be expired when ExpiresAt is in the past")
	}
}

func TestExchange_ExchangeTimeout(t *testing.T) {
	if ExchangeTimeout != 30*time.Second {
		t.Errorf("ExchangeTimeout = %v, want 30s", ExchangeTimeout)
	}
}

// ============================================================
// SetPeerCommitment Tests
// ============================================================

func TestExchange_SetPeerCommitment(t *testing.T) {
	ex, _ := NewExchange(peer.ID("test"), RoleInitiator, makeSignature(32))

	peerCommitment := makeSignature(32) // Commitments are also 32 bytes
	ex.SetPeerCommitment(peerCommitment)

	if len(ex.PeerCommitment) != 32 {
		t.Errorf("PeerCommitment length = %d, want 32", len(ex.PeerCommitment))
	}

	for i := range peerCommitment {
		if ex.PeerCommitment[i] != peerCommitment[i] {
			t.Errorf("PeerCommitment[%d] = %d, want %d", i, ex.PeerCommitment[i], peerCommitment[i])
		}
	}
}

func TestExchange_SetPeerCommitment_Overwrite(t *testing.T) {
	ex, _ := NewExchange(peer.ID("test"), RoleInitiator, makeSignature(32))

	commitment1 := makeSignature(32)
	commitment2 := makeSignature(32)

	ex.SetPeerCommitment(commitment1)
	ex.SetPeerCommitment(commitment2)

	// Should have the second commitment
	for i := range commitment2 {
		if ex.PeerCommitment[i] != commitment2[i] {
			t.Errorf("PeerCommitment should be overwritten with second value")
			break
		}
	}
}

// ============================================================
// SetPeerReveal Tests - Valid Cases
// ============================================================

func TestExchange_SetPeerReveal_Valid(t *testing.T) {
	ex, _ := NewExchange(peer.ID("test"), RoleInitiator, makeSignature(32))

	// Simulate peer's valid commit-reveal
	peerSig := makeSignature(32)
	peerSalt := makeSalt(16)
	peerCommitment := computeCommitment(peerSig, peerSalt)

	ex.SetPeerCommitment(peerCommitment)
	err := ex.SetPeerReveal(peerSig, peerSalt)

	if err != nil {
		t.Errorf("SetPeerReveal() error = %v, want nil", err)
	}

	// PeerSignature should be set
	for i := range peerSig {
		if ex.PeerSignature[i] != peerSig[i] {
			t.Error("PeerSignature should match revealed signature")
			break
		}
	}

	// PeerSalt should be set
	for i := range peerSalt {
		if ex.PeerSalt[i] != peerSalt[i] {
			t.Error("PeerSalt should match revealed salt")
			break
		}
	}
}

func TestExchange_SetPeerReveal_ValidLongerSalt(t *testing.T) {
	ex, _ := NewExchange(peer.ID("test"), RoleInitiator, makeSignature(32))

	// Simulate peer's valid commit-reveal with longer salt
	peerSig := makeSignature(32)
	peerSalt := makeSalt(32) // Longer salt is valid
	peerCommitment := computeCommitment(peerSig, peerSalt)

	ex.SetPeerCommitment(peerCommitment)
	err := ex.SetPeerReveal(peerSig, peerSalt)

	if err != nil {
		t.Errorf("SetPeerReveal() error = %v, want nil for longer salt", err)
	}
}

// ============================================================
// SetPeerReveal Tests - Invalid Cases
// ============================================================

func TestExchange_SetPeerReveal_Tampered(t *testing.T) {
	ex, _ := NewExchange(peer.ID("test"), RoleInitiator, makeSignature(32))

	// Peer commits to one signature but reveals different
	originalSig := makeSignature(32)
	peerSalt := makeSalt(16)
	peerCommitment := computeCommitment(originalSig, peerSalt)

	ex.SetPeerCommitment(peerCommitment)

	// Try to reveal different signature
	tamperedSig := makeSignature(32)
	err := ex.SetPeerReveal(tamperedSig, peerSalt)

	if err != ErrCommitmentMismatch {
		t.Errorf("SetPeerReveal() error = %v, want ErrCommitmentMismatch", err)
	}
	if ex.State != ExchangeStateFailed {
		t.Errorf("State = %v, want ExchangeStateFailed", ex.State)
	}
}

func TestExchange_SetPeerReveal_TamperedSalt(t *testing.T) {
	ex, _ := NewExchange(peer.ID("test"), RoleInitiator, makeSignature(32))

	peerSig := makeSignature(32)
	originalSalt := makeSalt(16)
	peerCommitment := computeCommitment(peerSig, originalSalt)

	ex.SetPeerCommitment(peerCommitment)

	// Try to reveal with different salt
	tamperedSalt := makeSalt(16)
	err := ex.SetPeerReveal(peerSig, tamperedSalt)

	if err != ErrCommitmentMismatch {
		t.Errorf("SetPeerReveal() error = %v, want ErrCommitmentMismatch", err)
	}
	if ex.State != ExchangeStateFailed {
		t.Errorf("State = %v, want ExchangeStateFailed", ex.State)
	}
}

func TestExchange_SetPeerReveal_InvalidSaltLength(t *testing.T) {
	ex, _ := NewExchange(peer.ID("test"), RoleInitiator, makeSignature(32))

	peerSig := makeSignature(32)
	shortSalt := makeSalt(8) // Too short
	// Note: commitment computed with short salt
	peerCommitment := computeCommitment(peerSig, shortSalt)

	ex.SetPeerCommitment(peerCommitment)

	err := ex.SetPeerReveal(peerSig, shortSalt)

	if err != ErrInvalidSalt {
		t.Errorf("SetPeerReveal() error = %v, want ErrInvalidSalt", err)
	}
	if ex.State != ExchangeStateFailed {
		t.Errorf("State = %v, want ExchangeStateFailed", ex.State)
	}
}

func TestExchange_SetPeerReveal_InvalidSignatureLength(t *testing.T) {
	ex, _ := NewExchange(peer.ID("test"), RoleInitiator, makeSignature(32))

	shortSig := makeSignature(16) // Too short
	peerSalt := makeSalt(16)
	peerCommitment := computeCommitment(shortSig, peerSalt)

	ex.SetPeerCommitment(peerCommitment)

	err := ex.SetPeerReveal(shortSig, peerSalt)

	if err != ErrMalformedSignature {
		t.Errorf("SetPeerReveal() error = %v, want ErrMalformedSignature", err)
	}
	if ex.State != ExchangeStateFailed {
		t.Errorf("State = %v, want ExchangeStateFailed", ex.State)
	}
}

func TestExchange_SetPeerReveal_NoCommitmentSet(t *testing.T) {
	ex, _ := NewExchange(peer.ID("test"), RoleInitiator, makeSignature(32))

	// Don't set peer commitment first
	peerSig := makeSignature(32)
	peerSalt := makeSalt(16)

	err := ex.SetPeerReveal(peerSig, peerSalt)

	// Should fail because commitment is nil/empty
	if err != ErrCommitmentMismatch {
		t.Errorf("SetPeerReveal() without commitment should fail with ErrCommitmentMismatch, got %v", err)
	}
	if ex.State != ExchangeStateFailed {
		t.Errorf("State = %v, want ExchangeStateFailed", ex.State)
	}
}

// ============================================================
// State Constants Tests
// ============================================================

func TestExchangeRole_Constants(t *testing.T) {
	// Verify role constants have expected values
	if RoleInitiator != 0 {
		t.Errorf("RoleInitiator = %d, want 0", RoleInitiator)
	}
	if RoleResponder != 1 {
		t.Errorf("RoleResponder = %d, want 1", RoleResponder)
	}
}

func TestExchangeState_Constants(t *testing.T) {
	// Verify state constants have expected values
	if ExchangeStatePending != 0 {
		t.Errorf("ExchangeStatePending = %d, want 0", ExchangeStatePending)
	}
	if ExchangeStateCommitSent != 1 {
		t.Errorf("ExchangeStateCommitSent = %d, want 1", ExchangeStateCommitSent)
	}
	if ExchangeStateCommitReceived != 2 {
		t.Errorf("ExchangeStateCommitReceived = %d, want 2", ExchangeStateCommitReceived)
	}
	if ExchangeStateRevealSent != 3 {
		t.Errorf("ExchangeStateRevealSent = %d, want 3", ExchangeStateRevealSent)
	}
	if ExchangeStateComplete != 4 {
		t.Errorf("ExchangeStateComplete = %d, want 4", ExchangeStateComplete)
	}
	if ExchangeStateFailed != 5 {
		t.Errorf("ExchangeStateFailed = %d, want 5", ExchangeStateFailed)
	}
}

// ============================================================
// Salt Uniqueness Tests
// ============================================================

func TestNewExchange_SaltUniqueness(t *testing.T) {
	// Create multiple exchanges and ensure salts are unique
	const numExchanges = 100
	salts := make(map[string]bool)

	for i := 0; i < numExchanges; i++ {
		ex, err := NewExchange(peer.ID("test"), RoleInitiator, makeSignature(32))
		if err != nil {
			t.Fatalf("NewExchange() error = %v", err)
		}

		key := string(ex.Salt)
		if salts[key] {
			t.Errorf("duplicate salt found at iteration %d", i)
		}
		salts[key] = true
	}
}

func TestNewExchange_CommitmentUniqueness(t *testing.T) {
	// Even with same signature, commitments should differ due to unique salts
	const numExchanges = 100
	commitments := make(map[string]bool)
	sig := makeSignature(32) // Same signature for all

	for i := 0; i < numExchanges; i++ {
		ex, err := NewExchange(peer.ID("test"), RoleInitiator, sig)
		if err != nil {
			t.Fatalf("NewExchange() error = %v", err)
		}

		key := string(ex.Commitment)
		if commitments[key] {
			t.Errorf("duplicate commitment found at iteration %d", i)
		}
		commitments[key] = true
	}
}

// ============================================================
// Benchmarks
// ============================================================

func BenchmarkNewExchange(b *testing.B) {
	sig := makeSignature(32)
	peerID := peer.ID("test-peer")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewExchange(peerID, RoleInitiator, sig)
	}
}

func BenchmarkSetPeerReveal(b *testing.B) {
	peerSig := makeSignature(32)
	peerSalt := makeSalt(16)
	peerCommitment := computeCommitment(peerSig, peerSalt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ex, _ := NewExchange(peer.ID("test"), RoleInitiator, makeSignature(32))
		ex.SetPeerCommitment(peerCommitment)
		ex.SetPeerReveal(peerSig, peerSalt)
	}
}

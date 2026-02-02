// Package discovery provides peer discovery mechanisms for the P2P network.
// This file tests the DHT bucket record types and signature lifecycle management.
package discovery

import (
	"bytes"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// Note: makeSignature and makeSalt helpers are defined in commitment_test.go

func TestBucketRecord_Serialization(t *testing.T) {
	peerID, err := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	if err != nil {
		t.Fatalf("Failed to decode peer ID: %v", err)
	}

	record := &BucketRecord{
		PeerID:    peerID,
		Addresses: []string{"/ip4/192.168.1.1/tcp/4001"},
		Timestamp: time.Now().Unix(),
		TTL:       3600,
	}

	data, err := BucketRecordToJSON(record)
	if err != nil {
		t.Fatalf("BucketRecordToJSON failed: %v", err)
	}

	parsed, err := BucketRecordFromJSON(data)
	if err != nil {
		t.Fatalf("BucketRecordFromJSON failed: %v", err)
	}

	if parsed.PeerID != record.PeerID {
		t.Errorf("PeerID mismatch: got %v, want %v", parsed.PeerID, record.PeerID)
	}

	if len(parsed.Addresses) != len(record.Addresses) {
		t.Errorf("Addresses length mismatch: got %d, want %d", len(parsed.Addresses), len(record.Addresses))
	} else {
		for i, addr := range record.Addresses {
			if parsed.Addresses[i] != addr {
				t.Errorf("Address[%d] mismatch: got %s, want %s", i, parsed.Addresses[i], addr)
			}
		}
	}

	if parsed.Timestamp != record.Timestamp {
		t.Errorf("Timestamp mismatch: got %d, want %d", parsed.Timestamp, record.Timestamp)
	}

	if parsed.TTL != record.TTL {
		t.Errorf("TTL mismatch: got %d, want %d", parsed.TTL, record.TTL)
	}
}

func TestBucketRecord_SerializationWithMultipleAddresses(t *testing.T) {
	peerID, err := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	if err != nil {
		t.Fatalf("Failed to decode peer ID: %v", err)
	}

	record := &BucketRecord{
		PeerID: peerID,
		Addresses: []string{
			"/ip4/192.168.1.1/tcp/4001",
			"/ip4/10.0.0.1/tcp/4001",
			"/ip6/::1/tcp/4001",
		},
		Timestamp: time.Now().Unix(),
		TTL:       7200,
	}

	data, err := BucketRecordToJSON(record)
	if err != nil {
		t.Fatalf("BucketRecordToJSON failed: %v", err)
	}

	parsed, err := BucketRecordFromJSON(data)
	if err != nil {
		t.Fatalf("BucketRecordFromJSON failed: %v", err)
	}

	if len(parsed.Addresses) != 3 {
		t.Errorf("Expected 3 addresses, got %d", len(parsed.Addresses))
	}
}

func TestBucketRecord_SerializationEmptyAddresses(t *testing.T) {
	peerID, err := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	if err != nil {
		t.Fatalf("Failed to decode peer ID: %v", err)
	}

	record := &BucketRecord{
		PeerID:    peerID,
		Addresses: []string{},
		Timestamp: time.Now().Unix(),
		TTL:       3600,
	}

	data, err := BucketRecordToJSON(record)
	if err != nil {
		t.Fatalf("BucketRecordToJSON failed: %v", err)
	}

	parsed, err := BucketRecordFromJSON(data)
	if err != nil {
		t.Fatalf("BucketRecordFromJSON failed: %v", err)
	}

	if len(parsed.Addresses) != 0 {
		t.Errorf("Expected empty addresses, got %d", len(parsed.Addresses))
	}
}

func TestBucketRecordFromJSON_InvalidJSON(t *testing.T) {
	_, err := BucketRecordFromJSON([]byte("invalid json"))
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestBucketRecordFromJSON_InvalidPeerID(t *testing.T) {
	data := []byte(`{"peer_id":"invalid-peer-id","addrs":[],"timestamp":123,"ttl":3600}`)
	_, err := BucketRecordFromJSON(data)
	if err == nil {
		t.Error("Expected error for invalid peer ID")
	}
}

func TestSignatureState_ShouldRegenerate(t *testing.T) {
	state := &SignatureState{
		Signature:   makeSignature(32),
		MonadHash:   []byte("hash1"),
		GeneratedAt: time.Now(),
	}

	// Same hash - no regeneration
	if state.ShouldRegenerate([]byte("hash1")) {
		t.Error("Should not regenerate when hash is the same")
	}

	// Different hash - regenerate
	if !state.ShouldRegenerate([]byte("hash2")) {
		t.Error("Should regenerate when hash is different")
	}

	// Nil signature - always regenerate
	state.Signature = nil
	if !state.ShouldRegenerate([]byte("hash1")) {
		t.Error("Should regenerate when signature is nil")
	}
}

func TestSignatureState_ShouldRegenerate_NilMonadHash(t *testing.T) {
	state := &SignatureState{
		Signature:   makeSignature(32),
		MonadHash:   nil,
		GeneratedAt: time.Now(),
	}

	// With a new hash and nil stored hash, should regenerate
	if !state.ShouldRegenerate([]byte("hash1")) {
		t.Error("Should regenerate when stored MonadHash is nil but new hash is provided")
	}

	// Both nil - should not regenerate
	if state.ShouldRegenerate(nil) {
		t.Error("Should not regenerate when both hashes are nil")
	}
}

func TestSignatureState_ShouldRepublish(t *testing.T) {
	state := &SignatureState{
		PublishedAt: time.Now(),
	}

	// Just published - no republish
	if state.ShouldRepublish() {
		t.Error("Should not republish immediately after publishing")
	}

	// Near expiry (55 minutes old) - should republish
	state.PublishedAt = time.Now().Add(-(SignatureTTL - RepublishBuffer + time.Second))
	if !state.ShouldRepublish() {
		t.Error("Should republish when near expiry")
	}
}

func TestSignatureState_ShouldRepublish_JustBeforeBuffer(t *testing.T) {
	state := &SignatureState{
		// Just before the buffer threshold (1 second margin for timing)
		PublishedAt: time.Now().Add(-(SignatureTTL - RepublishBuffer - time.Second)),
	}

	// Just before the buffer threshold, should not republish yet
	if state.ShouldRepublish() {
		t.Error("Should not republish before the buffer threshold")
	}
}

func TestSignatureState_ShouldRepublish_ZeroTime(t *testing.T) {
	state := &SignatureState{
		PublishedAt: time.Time{}, // Zero time
	}

	// Zero time should trigger republish
	if !state.ShouldRepublish() {
		t.Error("Should republish when PublishedAt is zero")
	}
}

func TestSignatureState_UpdateSignature(t *testing.T) {
	state := &SignatureState{}
	sig := makeSignature(32)
	hash := []byte("monad-hash")

	beforeUpdate := time.Now()
	state.UpdateSignature(sig, hash)
	afterUpdate := time.Now()

	if !bytes.Equal(state.Signature, sig) {
		t.Errorf("Signature mismatch: got %v, want %v", state.Signature, sig)
	}

	if !bytes.Equal(state.MonadHash, hash) {
		t.Errorf("MonadHash mismatch: got %v, want %v", state.MonadHash, hash)
	}

	if state.GeneratedAt.Before(beforeUpdate) || state.GeneratedAt.After(afterUpdate) {
		t.Errorf("GeneratedAt out of range: got %v, expected between %v and %v",
			state.GeneratedAt, beforeUpdate, afterUpdate)
	}
}

func TestSignatureState_UpdateSignature_Overwrites(t *testing.T) {
	state := &SignatureState{
		Signature:   []byte("old-sig"),
		MonadHash:   []byte("old-hash"),
		GeneratedAt: time.Now().Add(-time.Hour),
	}

	newSig := makeSignature(32)
	newHash := []byte("new-hash")

	state.UpdateSignature(newSig, newHash)

	if !bytes.Equal(state.Signature, newSig) {
		t.Error("Signature should be overwritten")
	}

	if !bytes.Equal(state.MonadHash, newHash) {
		t.Error("MonadHash should be overwritten")
	}
}

func TestSignatureState_MarkPublished(t *testing.T) {
	state := &SignatureState{
		Signature:   makeSignature(32),
		GeneratedAt: time.Now().Add(-time.Minute),
	}

	beforeMark := time.Now()
	state.MarkPublished()
	afterMark := time.Now()

	if state.PublishedAt.Before(beforeMark) || state.PublishedAt.After(afterMark) {
		t.Errorf("PublishedAt out of range: got %v, expected between %v and %v",
			state.PublishedAt, beforeMark, afterMark)
	}
}

func TestSignatureState_MarkPublished_Overwrites(t *testing.T) {
	oldTime := time.Now().Add(-time.Hour)
	state := &SignatureState{
		PublishedAt: oldTime,
	}

	state.MarkPublished()

	if state.PublishedAt.Equal(oldTime) {
		t.Error("PublishedAt should be overwritten")
	}
}

func TestConstants(t *testing.T) {
	// Verify constants have expected values
	if SignatureTTL != 1*time.Hour {
		t.Errorf("SignatureTTL should be 1 hour, got %v", SignatureTTL)
	}

	if RepublishBuffer != 5*time.Minute {
		t.Errorf("RepublishBuffer should be 5 minutes, got %v", RepublishBuffer)
	}

	if MinMonadDelta != 0.01 {
		t.Errorf("MinMonadDelta should be 0.01, got %v", MinMonadDelta)
	}
}

func TestBucketRecordToJSON_NilRecord(t *testing.T) {
	_, err := BucketRecordToJSON(nil)
	if err == nil {
		t.Error("Expected error for nil record")
	}
}

func TestBucketRecordFromJSON_EmptyData(t *testing.T) {
	_, err := BucketRecordFromJSON([]byte{})
	if err == nil {
		t.Error("Expected error for empty data")
	}
}

func TestSignatureState_ShouldRegenerate_EmptySignature(t *testing.T) {
	state := &SignatureState{
		Signature:   []byte{}, // Empty but not nil
		MonadHash:   []byte("hash1"),
		GeneratedAt: time.Now(),
	}

	// Empty signature should trigger regeneration
	if !state.ShouldRegenerate([]byte("hash1")) {
		t.Error("Should regenerate when signature is empty")
	}
}

func TestSignatureState_FullLifecycle(t *testing.T) {
	state := &SignatureState{}

	// Initially should need regeneration
	if !state.ShouldRegenerate([]byte("initial-hash")) {
		t.Error("New state should need regeneration")
	}

	// Update with initial signature
	sig1 := makeSignature(32)
	hash1 := []byte("hash-v1")
	state.UpdateSignature(sig1, hash1)

	// Should not need regeneration with same hash
	if state.ShouldRegenerate(hash1) {
		t.Error("Should not regenerate with same hash")
	}

	// Should need republish (never published)
	if !state.ShouldRepublish() {
		t.Error("Should republish when never published")
	}

	// Mark as published
	state.MarkPublished()

	// Now should not need republish
	if state.ShouldRepublish() {
		t.Error("Should not republish right after marking")
	}

	// Different hash triggers regeneration
	hash2 := []byte("hash-v2")
	if !state.ShouldRegenerate(hash2) {
		t.Error("Should regenerate with different hash")
	}
}

// Package discovery provides peer discovery mechanisms for the P2P network.
package discovery

import (
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// ============================================================
// DefaultLSHDiscoveryConfig Tests
// ============================================================

func TestDefaultLSHDiscoveryConfig(t *testing.T) {
	cfg := DefaultLSHDiscoveryConfig()

	if cfg.HammingThreshold != 64 {
		t.Errorf("HammingThreshold = %d, want 64", cfg.HammingThreshold)
	}
	if cfg.InitiationRateLimit != time.Minute {
		t.Errorf("InitiationRateLimit = %v, want 1m", cfg.InitiationRateLimit)
	}
	if cfg.ExchangeTimeout != 30*time.Second {
		t.Errorf("ExchangeTimeout = %v, want 30s", cfg.ExchangeTimeout)
	}
	if cfg.MaxPendingExchanges != 10 {
		t.Errorf("MaxPendingExchanges = %d, want 10", cfg.MaxPendingExchanges)
	}
}

// ============================================================
// NewLSHDiscoveryManager Tests
// ============================================================

func TestNewLSHDiscoveryManager(t *testing.T) {
	cfg := DefaultLSHDiscoveryConfig()
	dm := NewLSHDiscoveryManager(cfg)

	if dm == nil {
		t.Fatal("NewLSHDiscoveryManager returned nil")
	}
}

func TestNewLSHDiscoveryManager_InitializesEmptyMaps(t *testing.T) {
	cfg := DefaultLSHDiscoveryConfig()
	dm := NewLSHDiscoveryManager(cfg)

	// discoveredPeers should be initialized but empty
	if dm.GetDiscoveredPeerCount() != 0 {
		t.Errorf("GetDiscoveredPeerCount() = %d, want 0", dm.GetDiscoveredPeerCount())
	}

	// pendingExchanges should be initialized but empty
	if dm.GetPendingExchangeCount() != 0 {
		t.Errorf("GetPendingExchangeCount() = %d, want 0", dm.GetPendingExchangeCount())
	}
}

// ============================================================
// Rate Limiting Tests
// ============================================================

func TestLSHDiscoveryManager_RateLimit(t *testing.T) {
	cfg := DefaultLSHDiscoveryConfig()
	cfg.InitiationRateLimit = 100 * time.Millisecond // Shorter for testing
	dm := NewLSHDiscoveryManager(cfg)

	// First initiation allowed
	if !dm.CanInitiateHandshake() {
		t.Error("First handshake initiation should be allowed")
	}
	dm.RecordHandshakeInitiation()

	// Immediate second attempt blocked
	if dm.CanInitiateHandshake() {
		t.Error("Immediate second handshake initiation should be blocked")
	}

	// After rate limit window, allowed again
	time.Sleep(110 * time.Millisecond)
	if !dm.CanInitiateHandshake() {
		t.Error("Handshake initiation should be allowed after rate limit window")
	}
}

func TestLSHDiscoveryManager_RateLimit_ZeroLastInitiation(t *testing.T) {
	cfg := DefaultLSHDiscoveryConfig()
	dm := NewLSHDiscoveryManager(cfg)

	// When lastInitiation is zero (never initiated), should be allowed
	if !dm.CanInitiateHandshake() {
		t.Error("First handshake should always be allowed")
	}
}

func TestLSHDiscoveryManager_RateLimit_ConcurrentAccess(t *testing.T) {
	cfg := DefaultLSHDiscoveryConfig()
	cfg.InitiationRateLimit = 10 * time.Millisecond
	dm := NewLSHDiscoveryManager(cfg)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = dm.CanInitiateHandshake()
			dm.RecordHandshakeInitiation()
		}()
	}
	wg.Wait()
	// Should complete without race conditions
}

// ============================================================
// Retry Logic Tests
// ============================================================

func TestLSHDiscoveryManager_ShouldRetry(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	// Protocol violations - no retry
	if dm.ShouldRetry(ErrCommitmentMismatch) {
		t.Error("ErrCommitmentMismatch should not be retried")
	}
	if dm.ShouldRetry(ErrInvalidSalt) {
		t.Error("ErrInvalidSalt should not be retried")
	}
	if dm.ShouldRetry(ErrMalformedSignature) {
		t.Error("ErrMalformedSignature should not be retried")
	}

	// Transient errors - can retry
	if !dm.ShouldRetry(ErrStaleTimestamp) {
		t.Error("ErrStaleTimestamp should be retried")
	}
	if !dm.ShouldRetry(ErrRateLimited) {
		t.Error("ErrRateLimited should be retried")
	}
}

func TestLSHDiscoveryManager_ShouldRetry_UnknownError(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	// Unknown error types should not be retried
	unknownErr := DiscoveryError("unknown_error")
	if dm.ShouldRetry(unknownErr) {
		t.Error("Unknown errors should not be retried")
	}
}

func TestLSHDiscoveryManager_RetryBackoff(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	// Test exponential backoff
	if dm.RetryBackoff(0) != 5*time.Second {
		t.Errorf("RetryBackoff(0) = %v, want 5s", dm.RetryBackoff(0))
	}
	if dm.RetryBackoff(1) != 10*time.Second {
		t.Errorf("RetryBackoff(1) = %v, want 10s", dm.RetryBackoff(1))
	}
	if dm.RetryBackoff(2) != 20*time.Second {
		t.Errorf("RetryBackoff(2) = %v, want 20s", dm.RetryBackoff(2))
	}
	if dm.RetryBackoff(3) != 40*time.Second {
		t.Errorf("RetryBackoff(3) = %v, want 40s", dm.RetryBackoff(3))
	}

	// Test cap at 60 seconds
	if dm.RetryBackoff(4) != 60*time.Second {
		t.Errorf("RetryBackoff(4) = %v, want 60s (capped)", dm.RetryBackoff(4))
	}
	if dm.RetryBackoff(10) != 60*time.Second {
		t.Errorf("RetryBackoff(10) = %v, want 60s (capped)", dm.RetryBackoff(10))
	}
}

func TestLSHDiscoveryManager_RetryBackoff_NegativeCount(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	// Negative retry count should be treated as 0
	if dm.RetryBackoff(-1) != 5*time.Second {
		t.Errorf("RetryBackoff(-1) = %v, want 5s", dm.RetryBackoff(-1))
	}
}

// ============================================================
// Local Signature Tests
// ============================================================

func TestLSHDiscoveryManager_LocalSignature(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	sig := makeSignature(32)
	dm.SetLocalSignature(sig)

	got := dm.GetLocalSignature()
	if len(got) != len(sig) {
		t.Fatalf("GetLocalSignature() length = %d, want %d", len(got), len(sig))
	}

	for i := range sig {
		if got[i] != sig[i] {
			t.Errorf("GetLocalSignature()[%d] = %d, want %d", i, got[i], sig[i])
		}
	}
}

func TestLSHDiscoveryManager_LocalSignature_ReturnsCopy(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	sig := makeSignature(32)
	dm.SetLocalSignature(sig)

	got := dm.GetLocalSignature()

	// Ensure returned slice is a copy (mutating it doesn't affect internal)
	got[0] ^= 0xFF
	got2 := dm.GetLocalSignature()

	if got2[0] != sig[0] {
		t.Errorf("GetLocalSignature() should return a copy, internal state was modified")
	}
}

func TestLSHDiscoveryManager_LocalSignature_SetCopiesInput(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	sig := makeSignature(32)
	originalSig := make([]byte, 32)
	copy(originalSig, sig)

	dm.SetLocalSignature(sig)

	// Modify original signature
	sig[0] ^= 0xFF

	// Internal state should be unchanged
	got := dm.GetLocalSignature()
	if got[0] != originalSig[0] {
		t.Errorf("SetLocalSignature should copy input, internal state was modified by external change")
	}
}

func TestLSHDiscoveryManager_LocalSignature_NilReturnsNil(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	got := dm.GetLocalSignature()
	if got != nil {
		t.Errorf("GetLocalSignature() before SetLocalSignature should return nil, got %v", got)
	}
}

func TestLSHDiscoveryManager_LocalSignature_SetNil(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	// Set a signature first
	sig := makeSignature(32)
	dm.SetLocalSignature(sig)

	// Now set nil
	dm.SetLocalSignature(nil)

	got := dm.GetLocalSignature()
	if got != nil {
		t.Errorf("GetLocalSignature() after SetLocalSignature(nil) should return nil, got %v", got)
	}
}

func TestLSHDiscoveryManager_LocalSignature_ConcurrentAccess(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			sig := makeSignature(32)
			dm.SetLocalSignature(sig)
		}()
		go func() {
			defer wg.Done()
			_ = dm.GetLocalSignature()
		}()
	}
	wg.Wait()
	// Should complete without race conditions
}

// ============================================================
// Discovered Peer Management Tests
// ============================================================

func TestLSHDiscoveryManager_AddDiscoveredPeer(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	peerID := peer.ID("test-peer-1")
	sig := makeSignature(32)
	hammingDist := 10

	dm.AddDiscoveredPeer(peerID, sig, hammingDist)

	if dm.GetDiscoveredPeerCount() != 1 {
		t.Errorf("GetDiscoveredPeerCount() = %d, want 1", dm.GetDiscoveredPeerCount())
	}

	discovered := dm.GetDiscoveredPeer(peerID)
	if discovered == nil {
		t.Fatal("GetDiscoveredPeer returned nil for added peer")
	}
	if discovered.PeerID != peerID {
		t.Errorf("PeerID = %v, want %v", discovered.PeerID, peerID)
	}
	if discovered.HammingDistance != hammingDist {
		t.Errorf("HammingDistance = %d, want %d", discovered.HammingDistance, hammingDist)
	}
}

func TestLSHDiscoveryManager_GetDiscoveredPeer_NotFound(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	discovered := dm.GetDiscoveredPeer(peer.ID("nonexistent"))
	if discovered != nil {
		t.Error("GetDiscoveredPeer should return nil for unknown peer")
	}
}

func TestLSHDiscoveryManager_AddDiscoveredPeer_Update(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	peerID := peer.ID("test-peer-1")
	sig1 := makeSignature(32)
	sig2 := makeSignature(32) // Different signature

	// Add initial peer
	dm.AddDiscoveredPeer(peerID, sig1, 10)
	discovered1 := dm.GetDiscoveredPeer(peerID)
	firstDiscoveredAt := discovered1.DiscoveredAt

	// Wait a tiny bit to ensure time difference
	time.Sleep(1 * time.Millisecond)

	// Update the same peer with new signature and distance
	dm.AddDiscoveredPeer(peerID, sig2, 20)

	// Should still have only 1 peer
	if dm.GetDiscoveredPeerCount() != 1 {
		t.Errorf("GetDiscoveredPeerCount() = %d, want 1", dm.GetDiscoveredPeerCount())
	}

	discovered2 := dm.GetDiscoveredPeer(peerID)
	if discovered2 == nil {
		t.Fatal("GetDiscoveredPeer returned nil after update")
	}

	// HammingDistance should be updated
	if discovered2.HammingDistance != 20 {
		t.Errorf("HammingDistance = %d, want 20 (updated)", discovered2.HammingDistance)
	}

	// DiscoveredAt should remain the same (not updated)
	if !discovered2.DiscoveredAt.Equal(firstDiscoveredAt) {
		t.Errorf("DiscoveredAt should remain the same after update")
	}

	// LastExchange should be updated
	if !discovered2.LastExchange.After(firstDiscoveredAt) {
		t.Error("LastExchange should be updated to after DiscoveredAt")
	}
}

func TestLSHDiscoveryManager_RemoveDiscoveredPeer(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	peerID := peer.ID("test-peer-1")
	dm.AddDiscoveredPeer(peerID, makeSignature(32), 10)

	dm.RemoveDiscoveredPeer(peerID)

	if dm.GetDiscoveredPeerCount() != 0 {
		t.Errorf("GetDiscoveredPeerCount() = %d, want 0 after removal", dm.GetDiscoveredPeerCount())
	}
	if dm.GetDiscoveredPeer(peerID) != nil {
		t.Error("GetDiscoveredPeer should return nil after removal")
	}
}

func TestLSHDiscoveryManager_ListDiscoveredPeers(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	dm.AddDiscoveredPeer(peer.ID("peer-1"), makeSignature(32), 10)
	dm.AddDiscoveredPeer(peer.ID("peer-2"), makeSignature(32), 20)
	dm.AddDiscoveredPeer(peer.ID("peer-3"), makeSignature(32), 30)

	peers := dm.ListDiscoveredPeers()

	if len(peers) != 3 {
		t.Fatalf("ListDiscoveredPeers() length = %d, want 3", len(peers))
	}

	// Check all peers are present
	peerIDs := make(map[peer.ID]bool)
	for _, p := range peers {
		peerIDs[p.PeerID] = true
	}
	for _, id := range []peer.ID{"peer-1", "peer-2", "peer-3"} {
		if !peerIDs[id] {
			t.Errorf("ListDiscoveredPeers missing %v", id)
		}
	}
}

// ============================================================
// Pending Exchange Management Tests
// ============================================================

func TestLSHDiscoveryManager_AddPendingExchange(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())
	dm.SetLocalSignature(makeSignature(32))

	peerID := peer.ID("test-peer-1")
	ex, err := dm.AddPendingExchange(peerID, RoleInitiator)

	if err != nil {
		t.Fatalf("AddPendingExchange() error = %v", err)
	}
	if ex == nil {
		t.Fatal("AddPendingExchange() returned nil exchange")
	}
	if dm.GetPendingExchangeCount() != 1 {
		t.Errorf("GetPendingExchangeCount() = %d, want 1", dm.GetPendingExchangeCount())
	}
}

func TestLSHDiscoveryManager_AddPendingExchange_NoSignature(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())
	// Don't set local signature

	_, err := dm.AddPendingExchange(peer.ID("test"), RoleInitiator)
	if err == nil {
		t.Error("AddPendingExchange() should error when no local signature is set")
	}
}

func TestLSHDiscoveryManager_AddPendingExchange_MaxPending(t *testing.T) {
	cfg := DefaultLSHDiscoveryConfig()
	cfg.MaxPendingExchanges = 2
	dm := NewLSHDiscoveryManager(cfg)
	dm.SetLocalSignature(makeSignature(32))

	// Add up to max
	_, _ = dm.AddPendingExchange(peer.ID("peer-1"), RoleInitiator)
	_, _ = dm.AddPendingExchange(peer.ID("peer-2"), RoleInitiator)

	// Third should fail
	_, err := dm.AddPendingExchange(peer.ID("peer-3"), RoleInitiator)
	if err == nil {
		t.Error("AddPendingExchange() should error when max pending reached")
	}
}

func TestLSHDiscoveryManager_GetPendingExchange(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())
	dm.SetLocalSignature(makeSignature(32))

	peerID := peer.ID("test-peer-1")
	_, _ = dm.AddPendingExchange(peerID, RoleInitiator)

	ex := dm.GetPendingExchange(peerID)
	if ex == nil {
		t.Fatal("GetPendingExchange returned nil for added exchange")
	}
	if ex.PeerID != peerID {
		t.Errorf("PeerID = %v, want %v", ex.PeerID, peerID)
	}
}

func TestLSHDiscoveryManager_GetPendingExchange_NotFound(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	ex := dm.GetPendingExchange(peer.ID("nonexistent"))
	if ex != nil {
		t.Error("GetPendingExchange should return nil for unknown peer")
	}
}

func TestLSHDiscoveryManager_RemovePendingExchange(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())
	dm.SetLocalSignature(makeSignature(32))

	peerID := peer.ID("test-peer-1")
	_, _ = dm.AddPendingExchange(peerID, RoleInitiator)

	dm.RemovePendingExchange(peerID)

	if dm.GetPendingExchangeCount() != 0 {
		t.Errorf("GetPendingExchangeCount() = %d, want 0 after removal", dm.GetPendingExchangeCount())
	}
}

// ============================================================
// Config Access Tests
// ============================================================

func TestLSHDiscoveryManager_Config(t *testing.T) {
	cfg := DefaultLSHDiscoveryConfig()
	cfg.HammingThreshold = 100
	dm := NewLSHDiscoveryManager(cfg)

	got := dm.Config()
	if got.HammingThreshold != 100 {
		t.Errorf("Config().HammingThreshold = %d, want 100", got.HammingThreshold)
	}
}

// ============================================================
// Constants Tests
// ============================================================

func TestRetryConstants(t *testing.T) {
	if MaxExchangeRetries != 3 {
		t.Errorf("MaxExchangeRetries = %d, want 3", MaxExchangeRetries)
	}
	if RetryBackoffBase != 5*time.Second {
		t.Errorf("RetryBackoffBase = %v, want 5s", RetryBackoffBase)
	}
	if RetryBackoffMax != 60*time.Second {
		t.Errorf("RetryBackoffMax = %v, want 60s", RetryBackoffMax)
	}
}

// ============================================================
// Hamming Distance Check Tests
// ============================================================

func TestLSHDiscoveryManager_IsWithinThreshold(t *testing.T) {
	cfg := DefaultLSHDiscoveryConfig()
	cfg.HammingThreshold = 64
	dm := NewLSHDiscoveryManager(cfg)

	// Within threshold
	if !dm.IsWithinThreshold(0) {
		t.Error("IsWithinThreshold(0) should be true")
	}
	if !dm.IsWithinThreshold(64) {
		t.Error("IsWithinThreshold(64) should be true")
	}

	// Outside threshold
	if dm.IsWithinThreshold(65) {
		t.Error("IsWithinThreshold(65) should be false")
	}
	if dm.IsWithinThreshold(100) {
		t.Error("IsWithinThreshold(100) should be false")
	}
}

// ============================================================
// Cleanup Expired Exchanges Tests
// ============================================================

func TestLSHDiscoveryManager_CleanupExpiredExchanges(t *testing.T) {
	cfg := DefaultLSHDiscoveryConfig()
	cfg.ExchangeTimeout = 50 * time.Millisecond
	dm := NewLSHDiscoveryManager(cfg)
	dm.SetLocalSignature(makeSignature(32))

	// Add an exchange
	peerID := peer.ID("test-peer-1")
	ex, _ := dm.AddPendingExchange(peerID, RoleInitiator)

	// Set expiry to past
	ex.ExpiresAt = time.Now().Add(-time.Second)

	// Cleanup should remove it
	removed := dm.CleanupExpiredExchanges()
	if removed != 1 {
		t.Errorf("CleanupExpiredExchanges() = %d, want 1", removed)
	}
	if dm.GetPendingExchangeCount() != 0 {
		t.Errorf("GetPendingExchangeCount() = %d, want 0 after cleanup", dm.GetPendingExchangeCount())
	}
}

func TestLSHDiscoveryManager_CleanupExpiredExchanges_KeepsValid(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())
	dm.SetLocalSignature(makeSignature(32))

	// Add a non-expired exchange
	_, _ = dm.AddPendingExchange(peer.ID("test-peer-1"), RoleInitiator)

	// Cleanup should not remove it
	removed := dm.CleanupExpiredExchanges()
	if removed != 0 {
		t.Errorf("CleanupExpiredExchanges() = %d, want 0 (no expired exchanges)", removed)
	}
	if dm.GetPendingExchangeCount() != 1 {
		t.Errorf("GetPendingExchangeCount() = %d, want 1 (valid exchange kept)", dm.GetPendingExchangeCount())
	}
}

// ============================================================
// Benchmarks
// ============================================================

func BenchmarkLSHDiscoveryManager_CanInitiateHandshake(b *testing.B) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dm.CanInitiateHandshake()
	}
}

func BenchmarkLSHDiscoveryManager_RetryBackoff(b *testing.B) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dm.RetryBackoff(i % 5)
	}
}

func BenchmarkLSHDiscoveryManager_LocalSignature(b *testing.B) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())
	sig := makeSignature(32)
	dm.SetLocalSignature(sig)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dm.GetLocalSignature()
	}
}

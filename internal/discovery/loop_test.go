// Package discovery provides peer discovery mechanisms for the P2P network.
package discovery

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

// ============================================================
// ShouldInitiateExchange Tests
// ============================================================

func TestDiscoveryManager_ShouldInitiateExchange(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	localLow := peer.ID("AAAA")
	remoteHigh := peer.ID("ZZZZ")

	// Lower peer ID should initiate
	require.True(t, dm.ShouldInitiateExchange(localLow, remoteHigh))
	// Higher peer ID should not initiate
	require.False(t, dm.ShouldInitiateExchange(remoteHigh, localLow))
}

func TestDiscoveryManager_ShouldInitiateExchange_EqualIDs(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	sameID := peer.ID("AAAA")
	// Equal IDs should not initiate (deadlock prevention)
	require.False(t, dm.ShouldInitiateExchange(sameID, sameID))
}

// ============================================================
// InitiateExchange Tests
// ============================================================

func TestDiscoveryManager_InitiateExchange(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())
	dm.SetLocalSignature(makeSignature(32))

	peerID := peer.ID("test-peer")
	ex, err := dm.InitiateExchange(peerID)
	require.NoError(t, err)
	require.NotNil(t, ex)
	require.Equal(t, RoleInitiator, ex.Role)
	require.Equal(t, peerID, ex.PeerID)

	// Verify exchange is in pending exchanges
	pendingEx := dm.GetPendingExchange(peerID)
	require.NotNil(t, pendingEx)
	require.Equal(t, ex, pendingEx)
}

func TestDiscoveryManager_InitiateExchange_DuplicatePeer(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())
	dm.SetLocalSignature(makeSignature(32))

	peerID := peer.ID("test-peer")
	_, err := dm.InitiateExchange(peerID)
	require.NoError(t, err)

	// Second initiate with same peer should fail
	_, err = dm.InitiateExchange(peerID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already pending")
}

func TestDiscoveryManager_InitiateExchange_NoSignature(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())
	// Don't set local signature

	peerID := peer.ID("test-peer")
	_, err := dm.InitiateExchange(peerID)
	require.Error(t, err)
}

func TestDiscoveryManager_InitiateExchange_MaxLimit(t *testing.T) {
	cfg := DefaultLSHDiscoveryConfig()
	cfg.MaxPendingExchanges = 2
	dm := NewLSHDiscoveryManager(cfg)
	dm.SetLocalSignature(makeSignature(32))

	// Fill up to limit
	_, err := dm.InitiateExchange(peer.ID("peer1"))
	require.NoError(t, err)
	_, err = dm.InitiateExchange(peer.ID("peer2"))
	require.NoError(t, err)

	// Third should fail
	_, err = dm.InitiateExchange(peer.ID("peer3"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "max pending")
}

func TestDiscoveryManager_InitiateExchange_Concurrent(t *testing.T) {
	cfg := DefaultLSHDiscoveryConfig()
	cfg.MaxPendingExchanges = 100
	dm := NewLSHDiscoveryManager(cfg)
	dm.SetLocalSignature(makeSignature(32))

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			peerID := peer.ID(string(rune('A' + idx)))
			_, _ = dm.InitiateExchange(peerID)
		}(i)
	}
	wg.Wait()
	// Should complete without race conditions
}

// ============================================================
// CompleteExchange Tests
// ============================================================

func TestDiscoveryManager_CompleteExchange(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())
	dm.SetLocalSignature(makeSignature(32))

	peerID := peer.ID("test-peer")
	_, err := dm.InitiateExchange(peerID)
	require.NoError(t, err)

	peerSig := makeSignature(32)
	hammingDistance := 20
	dm.CompleteExchange(peerID, peerSig, hammingDistance)

	// Should be in discovered peers now
	discovered := dm.GetDiscoveredPeer(peerID)
	require.NotNil(t, discovered)
	require.Equal(t, hammingDistance, discovered.HammingDistance)
	require.Equal(t, peerID, discovered.PeerID)

	// Should not be in pending anymore
	pendingEx := dm.GetPendingExchange(peerID)
	require.Nil(t, pendingEx)
}

func TestDiscoveryManager_CompleteExchange_NoPending(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())
	dm.SetLocalSignature(makeSignature(32))

	peerID := peer.ID("test-peer")
	peerSig := makeSignature(32)

	// Complete without pending exchange should still add to discovered
	dm.CompleteExchange(peerID, peerSig, 15)

	// Should still be added to discovered peers
	discovered := dm.GetDiscoveredPeer(peerID)
	require.NotNil(t, discovered)
	require.Equal(t, 15, discovered.HammingDistance)
}

func TestDiscoveryManager_CompleteExchange_SignatureCopied(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())
	dm.SetLocalSignature(makeSignature(32))

	peerID := peer.ID("test-peer")
	_, _ = dm.InitiateExchange(peerID)

	peerSig := makeSignature(32)
	originalByte := peerSig[0]
	dm.CompleteExchange(peerID, peerSig, 20)

	// Modify original signature
	peerSig[0] ^= 0xFF

	// Discovered peer should have the original value (was copied)
	discovered := dm.GetDiscoveredPeer(peerID)
	require.Equal(t, originalByte, discovered.Signature[0])
}

// ============================================================
// FailExchange Tests
// ============================================================

func TestDiscoveryManager_FailExchange(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())
	dm.SetLocalSignature(makeSignature(32))

	peerID := peer.ID("test-peer")
	ex, err := dm.InitiateExchange(peerID)
	require.NoError(t, err)
	require.Equal(t, ExchangeStatePending, ex.State)

	// Fail the exchange
	dm.FailExchange(peerID, nil)

	// Should not be in pending anymore
	pendingEx := dm.GetPendingExchange(peerID)
	require.Nil(t, pendingEx)

	// Should not be in discovered peers
	discovered := dm.GetDiscoveredPeer(peerID)
	require.Nil(t, discovered)
}

func TestDiscoveryManager_FailExchange_NoPending(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	// Fail a non-existent exchange should not panic
	dm.FailExchange(peer.ID("nonexistent"), nil)
}

// ============================================================
// GetPendingExchange Extended Tests
// ============================================================

func TestDiscoveryManager_GetPendingExchange_ReturnsExistsFlag(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())
	dm.SetLocalSignature(makeSignature(32))

	peerID := peer.ID("test-peer")

	// Before adding
	ex, exists := dm.GetPendingExchangeWithExists(peerID)
	require.False(t, exists)
	require.Nil(t, ex)

	// After adding
	_, _ = dm.InitiateExchange(peerID)
	ex, exists = dm.GetPendingExchangeWithExists(peerID)
	require.True(t, exists)
	require.NotNil(t, ex)
}

// ============================================================
// DiscoveryLoop Tests
// ============================================================

func TestDiscoveryLoop_StopsOnContextCancel(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		dm.DiscoveryLoop(ctx)
		close(done)
	}()

	// Give loop a moment to start
	time.Sleep(10 * time.Millisecond)

	cancel()

	select {
	case <-done:
		// Loop exited correctly
	case <-time.After(time.Second):
		t.Fatal("discovery loop did not exit on context cancel")
	}
}

func TestDiscoveryLoop_ImmediateContextCancel(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	done := make(chan struct{})
	go func() {
		dm.DiscoveryLoop(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Loop exited correctly
	case <-time.After(time.Second):
		t.Fatal("discovery loop did not exit on already-cancelled context")
	}
}

// ============================================================
// discoverBucketPeers Tests
// ============================================================

func TestDiscoverBucketPeers_NoSignature(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())

	// Should not panic without a signature
	dm.discoverBucketPeers(context.Background())
}

func TestDiscoverBucketPeers_WithSignature(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())
	dm.SetLocalSignature(makeSignature(32))

	// Should not panic with a signature
	dm.discoverBucketPeers(context.Background())
}

// ============================================================
// Integration Tests for Exchange Lifecycle
// ============================================================

func TestExchangeLifecycle_InitiateToComplete(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())
	dm.SetLocalSignature(makeSignature(32))

	peerID := peer.ID("test-peer")

	// 1. Initiate
	ex, err := dm.InitiateExchange(peerID)
	require.NoError(t, err)
	require.NotNil(t, ex)
	require.Equal(t, 1, dm.GetPendingExchangeCount())
	require.Equal(t, 0, dm.GetDiscoveredPeerCount())

	// 2. Complete
	dm.CompleteExchange(peerID, makeSignature(32), 25)
	require.Equal(t, 0, dm.GetPendingExchangeCount())
	require.Equal(t, 1, dm.GetDiscoveredPeerCount())
}

func TestExchangeLifecycle_InitiateToFail(t *testing.T) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())
	dm.SetLocalSignature(makeSignature(32))

	peerID := peer.ID("test-peer")

	// 1. Initiate
	_, err := dm.InitiateExchange(peerID)
	require.NoError(t, err)
	require.Equal(t, 1, dm.GetPendingExchangeCount())

	// 2. Fail
	dm.FailExchange(peerID, nil)
	require.Equal(t, 0, dm.GetPendingExchangeCount())
	require.Equal(t, 0, dm.GetDiscoveredPeerCount())
}

func TestExchangeLifecycle_MultipleExchanges(t *testing.T) {
	cfg := DefaultLSHDiscoveryConfig()
	cfg.MaxPendingExchanges = 10
	dm := NewLSHDiscoveryManager(cfg)
	dm.SetLocalSignature(makeSignature(32))

	// Initiate multiple exchanges
	for i := 0; i < 5; i++ {
		peerID := peer.ID(string(rune('A' + i)))
		_, err := dm.InitiateExchange(peerID)
		require.NoError(t, err)
	}
	require.Equal(t, 5, dm.GetPendingExchangeCount())

	// Complete some, fail others
	dm.CompleteExchange(peer.ID("A"), makeSignature(32), 10)
	dm.CompleteExchange(peer.ID("B"), makeSignature(32), 20)
	dm.FailExchange(peer.ID("C"), nil)
	dm.CompleteExchange(peer.ID("D"), makeSignature(32), 30)
	dm.FailExchange(peer.ID("E"), nil)

	require.Equal(t, 0, dm.GetPendingExchangeCount())
	require.Equal(t, 3, dm.GetDiscoveredPeerCount())
}

// ============================================================
// Benchmarks
// ============================================================

func BenchmarkDiscoveryManager_ShouldInitiateExchange(b *testing.B) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())
	localID := peer.ID("AAAA")
	remoteID := peer.ID("ZZZZ")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dm.ShouldInitiateExchange(localID, remoteID)
	}
}

func BenchmarkDiscoveryManager_InitiateExchange(b *testing.B) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())
	dm.SetLocalSignature(makeSignature(32))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		peerID := peer.ID(string(rune(i % 65536)))
		dm.InitiateExchange(peerID)
		dm.RemovePendingExchange(peerID)
	}
}

func BenchmarkDiscoveryManager_CompleteExchange(b *testing.B) {
	dm := NewLSHDiscoveryManager(DefaultLSHDiscoveryConfig())
	dm.SetLocalSignature(makeSignature(32))
	sig := makeSignature(32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		peerID := peer.ID(string(rune(i % 65536)))
		dm.InitiateExchange(peerID)
		dm.CompleteExchange(peerID, sig, 20)
		dm.RemoveDiscoveredPeer(peerID)
	}
}

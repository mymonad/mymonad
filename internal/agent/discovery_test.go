package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mymonad/mymonad/pkg/lsh"
	"github.com/mymonad/mymonad/pkg/monad"
)

// ============================================================
// Visibility Mode Tests
// ============================================================

func TestVisibilityModeValues(t *testing.T) {
	// Verify visibility mode values are distinct
	if VisibilityActive == VisibilityPassive {
		t.Error("VisibilityActive and VisibilityPassive should be distinct")
	}
	if VisibilityPassive == VisibilityHidden {
		t.Error("VisibilityPassive and VisibilityHidden should be distinct")
	}
	if VisibilityActive == VisibilityHidden {
		t.Error("VisibilityActive and VisibilityHidden should be distinct")
	}
}

func TestVisibilityModeOrdering(t *testing.T) {
	// Verify expected ordering: Active=0, Passive=1, Hidden=2
	if VisibilityActive != 0 {
		t.Errorf("VisibilityActive should be 0, got %d", VisibilityActive)
	}
	if VisibilityPassive != 1 {
		t.Errorf("VisibilityPassive should be 1, got %d", VisibilityPassive)
	}
	if VisibilityHidden != 2 {
		t.Errorf("VisibilityHidden should be 2, got %d", VisibilityHidden)
	}
}

// ============================================================
// Discovery Constructor Tests
// ============================================================

func TestNewDiscovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	host, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Close()

	dht, err := NewDHT(ctx, host)
	if err != nil {
		t.Fatalf("NewDHT failed: %v", err)
	}
	defer dht.Close()

	d := NewDiscovery(host, dht)
	if d == nil {
		t.Fatal("NewDiscovery returned nil")
	}

	// Default visibility should be Active
	if d.Visibility() != VisibilityActive {
		t.Errorf("Default visibility should be Active, got %d", d.Visibility())
	}
}

func TestNewDiscoveryWithNilHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	host, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Close()

	dht, err := NewDHT(ctx, host)
	if err != nil {
		t.Fatalf("NewDHT failed: %v", err)
	}
	defer dht.Close()

	d := NewDiscovery(nil, dht)
	if d != nil {
		t.Error("NewDiscovery should return nil when host is nil")
	}
}

func TestNewDiscoveryWithNilDHT(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	host, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Close()

	d := NewDiscovery(host, nil)
	if d != nil {
		t.Error("NewDiscovery should return nil when DHT is nil")
	}
}

// ============================================================
// Visibility Mode Setter Tests
// ============================================================

func TestSetVisibility(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	host, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Close()

	dht, err := NewDHT(ctx, host)
	if err != nil {
		t.Fatalf("NewDHT failed: %v", err)
	}
	defer dht.Close()

	d := NewDiscovery(host, dht)

	// Test setting to Passive
	d.SetVisibility(VisibilityPassive)
	if d.Visibility() != VisibilityPassive {
		t.Errorf("Visibility should be Passive after SetVisibility, got %d", d.Visibility())
	}

	// Test setting to Hidden
	d.SetVisibility(VisibilityHidden)
	if d.Visibility() != VisibilityHidden {
		t.Errorf("Visibility should be Hidden after SetVisibility, got %d", d.Visibility())
	}

	// Test setting back to Active
	d.SetVisibility(VisibilityActive)
	if d.Visibility() != VisibilityActive {
		t.Errorf("Visibility should be Active after SetVisibility, got %d", d.Visibility())
	}
}

func TestSetVisibilityConcurrent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	host, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Close()

	dht, err := NewDHT(ctx, host)
	if err != nil {
		t.Fatalf("NewDHT failed: %v", err)
	}
	defer dht.Close()

	d := NewDiscovery(host, dht)

	var wg sync.WaitGroup
	modes := []VisibilityMode{VisibilityActive, VisibilityPassive, VisibilityHidden}

	// Run concurrent visibility changes
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			d.SetVisibility(modes[idx%3])
			_ = d.Visibility() // Read concurrently
		}(i)
	}

	wg.Wait()
	// Should complete without race condition
}

// ============================================================
// Signature Update Tests
// ============================================================

func TestUpdateSignature(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	host, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Close()

	dht, err := NewDHT(ctx, host)
	if err != nil {
		t.Fatalf("NewDHT failed: %v", err)
	}
	defer dht.Close()

	d := NewDiscovery(host, dht)

	// Create a test signature
	sig := createTestMonadSignature(t)

	// Update signature should succeed
	err = d.UpdateSignature(sig)
	if err != nil {
		t.Errorf("UpdateSignature failed: %v", err)
	}

	// Verify signature is stored
	if d.Signature() == nil {
		t.Error("Signature should be stored after UpdateSignature")
	}
}

func TestUpdateSignatureNil(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	host, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Close()

	dht, err := NewDHT(ctx, host)
	if err != nil {
		t.Fatalf("NewDHT failed: %v", err)
	}
	defer dht.Close()

	d := NewDiscovery(host, dht)

	// Update with nil signature should return error
	err = d.UpdateSignature(nil)
	if err == nil {
		t.Error("UpdateSignature with nil should return error")
	}
}

func TestUpdateSignatureHiddenMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	host, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Close()

	dht, err := NewDHT(ctx, host)
	if err != nil {
		t.Fatalf("NewDHT failed: %v", err)
	}
	defer dht.Close()

	d := NewDiscovery(host, dht)
	d.SetVisibility(VisibilityHidden)

	sig := createTestMonadSignature(t)

	// Update signature in hidden mode should still succeed (stores locally)
	// but should not publish to DHT
	err = d.UpdateSignature(sig)
	if err != nil {
		t.Errorf("UpdateSignature in hidden mode should succeed: %v", err)
	}

	// Signature should be stored locally
	if d.Signature() == nil {
		t.Error("Signature should be stored even in hidden mode")
	}
}

// ============================================================
// Bucket Extraction Tests
// ============================================================

func TestExtractBuckets(t *testing.T) {
	// Test bucket extraction from a known signature
	sig := lsh.NewSignature(16) // 16 bits = 4 buckets of 4 bits each

	// Set bits: 0110 1001 1111 0000 (buckets: 0110=6, 1001=9, 1111=15, 0000=0)
	// Note: bit ordering is LSB first in each bucket
	sig.SetBit(1, true)  // bucket 0, bit 1
	sig.SetBit(2, true)  // bucket 0, bit 2
	sig.SetBit(4, true)  // bucket 1, bit 0
	sig.SetBit(7, true)  // bucket 1, bit 3
	sig.SetBit(8, true)  // bucket 2, bit 0
	sig.SetBit(9, true)  // bucket 2, bit 1
	sig.SetBit(10, true) // bucket 2, bit 2
	sig.SetBit(11, true) // bucket 2, bit 3

	buckets := ExtractBuckets(sig, 4)

	if len(buckets) != 4 {
		t.Fatalf("Expected 4 buckets, got %d", len(buckets))
	}

	// Verify bucket values
	expected := []uint64{6, 9, 15, 0}
	for i, exp := range expected {
		if buckets[i] != exp {
			t.Errorf("Bucket %d: expected %d, got %d", i, exp, buckets[i])
		}
	}
}

func TestExtractBucketsEmptySignature(t *testing.T) {
	sig := lsh.NewSignature(0)

	buckets := ExtractBuckets(sig, 4)

	if len(buckets) != 0 {
		t.Errorf("Empty signature should produce empty buckets, got %d buckets", len(buckets))
	}
}

func TestExtractBucketsNonDivisible(t *testing.T) {
	// 10 bits with 4-bit buckets = 2 full buckets + 2 remaining bits
	sig := lsh.NewSignature(10)
	sig.SetBit(0, true) // First bucket bit 0
	sig.SetBit(8, true) // Third (partial) bucket bit 0

	buckets := ExtractBuckets(sig, 4)

	// Should have 3 buckets: 2 full + 1 partial
	if len(buckets) != 3 {
		t.Errorf("Expected 3 buckets for 10 bits with 4-bit buckets, got %d", len(buckets))
	}
}

// ============================================================
// DHT Key Generation Tests
// ============================================================

func TestBucketToDHTKey(t *testing.T) {
	key := BucketToDHTKey(0, 6)
	expected := "/mymonad/lsh/0/6"

	if key != expected {
		t.Errorf("BucketToDHTKey(0, 6): got %q, want %q", key, expected)
	}
}

func TestBucketToDHTKeyMultipleBuckets(t *testing.T) {
	testCases := []struct {
		prefix   int
		value    uint64
		expected string
	}{
		{0, 0, "/mymonad/lsh/0/0"},
		{1, 9, "/mymonad/lsh/1/9"},
		{2, 15, "/mymonad/lsh/2/15"},
		{10, 255, "/mymonad/lsh/10/255"},
	}

	for _, tc := range testCases {
		key := BucketToDHTKey(tc.prefix, tc.value)
		if key != tc.expected {
			t.Errorf("BucketToDHTKey(%d, %d): got %q, want %q",
				tc.prefix, tc.value, key, tc.expected)
		}
	}
}

// ============================================================
// Publish Buckets Tests
// ============================================================

func TestPublishBucketsActiveMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create two nodes to form a minimal network
	host1, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost 1 failed: %v", err)
	}
	defer host1.Close()

	host2, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost 2 failed: %v", err)
	}
	defer host2.Close()

	dht1, err := NewDHT(ctx, host1)
	if err != nil {
		t.Fatalf("NewDHT 1 failed: %v", err)
	}
	defer dht1.Close()

	dht2, err := NewDHT(ctx, host2)
	if err != nil {
		t.Fatalf("NewDHT 2 failed: %v", err)
	}
	defer dht2.Close()

	// Connect nodes
	err = host2.Connect(ctx, host1.AddrInfo())
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	err = dht1.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("Bootstrap 1 failed: %v", err)
	}

	err = dht2.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("Bootstrap 2 failed: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	// Create discovery with signature
	d := NewDiscovery(host1, dht1)
	sig := createTestMonadSignature(t)
	err = d.UpdateSignature(sig)
	if err != nil {
		t.Fatalf("UpdateSignature failed: %v", err)
	}

	// Publish buckets
	err = d.PublishBuckets(ctx)
	if err != nil {
		t.Errorf("PublishBuckets failed: %v", err)
	}
}

func TestPublishBucketsHiddenMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	host, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Close()

	dht, err := NewDHT(ctx, host)
	if err != nil {
		t.Fatalf("NewDHT failed: %v", err)
	}
	defer dht.Close()

	d := NewDiscovery(host, dht)
	d.SetVisibility(VisibilityHidden)

	sig := createTestMonadSignature(t)
	err = d.UpdateSignature(sig)
	if err != nil {
		t.Fatalf("UpdateSignature failed: %v", err)
	}

	// PublishBuckets should succeed but do nothing in hidden mode
	err = d.PublishBuckets(ctx)
	if err != nil {
		t.Errorf("PublishBuckets in hidden mode should not return error: %v", err)
	}
}

func TestPublishBucketsNoSignature(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	host, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Close()

	dht, err := NewDHT(ctx, host)
	if err != nil {
		t.Fatalf("NewDHT failed: %v", err)
	}
	defer dht.Close()

	d := NewDiscovery(host, dht)

	// PublishBuckets without a signature should return error
	err = d.PublishBuckets(ctx)
	if err == nil {
		t.Error("PublishBuckets without signature should return error")
	}
}

// ============================================================
// Find Similar Tests
// ============================================================

func TestFindSimilarActiveMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create two nodes
	host1, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost 1 failed: %v", err)
	}
	defer host1.Close()

	host2, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost 2 failed: %v", err)
	}
	defer host2.Close()

	dht1, err := NewDHT(ctx, host1)
	if err != nil {
		t.Fatalf("NewDHT 1 failed: %v", err)
	}
	defer dht1.Close()

	dht2, err := NewDHT(ctx, host2)
	if err != nil {
		t.Fatalf("NewDHT 2 failed: %v", err)
	}
	defer dht2.Close()

	// Connect nodes
	err = host2.Connect(ctx, host1.AddrInfo())
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	err = dht1.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("Bootstrap 1 failed: %v", err)
	}

	err = dht2.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("Bootstrap 2 failed: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	// Create discoveries with similar signatures
	d1 := NewDiscovery(host1, dht1)
	d2 := NewDiscovery(host2, dht2)

	// Use same signature for both (they should find each other)
	sig := createTestMonadSignature(t)
	err = d1.UpdateSignature(sig)
	if err != nil {
		t.Fatalf("UpdateSignature 1 failed: %v", err)
	}
	err = d2.UpdateSignature(sig)
	if err != nil {
		t.Fatalf("UpdateSignature 2 failed: %v", err)
	}

	// Publish from node 1
	err = d1.PublishBuckets(ctx)
	if err != nil {
		t.Fatalf("PublishBuckets 1 failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Find similar from node 2
	peers, err := d2.FindSimilar(ctx, 10)
	if err != nil {
		t.Fatalf("FindSimilar failed: %v", err)
	}

	// Should find at least node 1
	found := false
	for _, p := range peers {
		if p.ID == host1.ID() {
			found = true
			break
		}
	}

	if !found {
		t.Error("FindSimilar should find peer with similar signature")
	}
}

func TestFindSimilarHiddenMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	host, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Close()

	dht, err := NewDHT(ctx, host)
	if err != nil {
		t.Fatalf("NewDHT failed: %v", err)
	}
	defer dht.Close()

	d := NewDiscovery(host, dht)
	d.SetVisibility(VisibilityHidden)

	sig := createTestMonadSignature(t)
	err = d.UpdateSignature(sig)
	if err != nil {
		t.Fatalf("UpdateSignature failed: %v", err)
	}

	// FindSimilar in hidden mode should return empty (no querying)
	peers, err := d.FindSimilar(ctx, 10)
	if err != nil {
		t.Errorf("FindSimilar in hidden mode should not return error: %v", err)
	}

	if len(peers) != 0 {
		t.Errorf("FindSimilar in hidden mode should return empty, got %d peers", len(peers))
	}
}

func TestFindSimilarPassiveMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	host, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Close()

	dht, err := NewDHT(ctx, host)
	if err != nil {
		t.Fatalf("NewDHT failed: %v", err)
	}
	defer dht.Close()

	d := NewDiscovery(host, dht)
	d.SetVisibility(VisibilityPassive)

	sig := createTestMonadSignature(t)
	err = d.UpdateSignature(sig)
	if err != nil {
		t.Fatalf("UpdateSignature failed: %v", err)
	}

	// FindSimilar in passive mode should return empty (no querying)
	peers, err := d.FindSimilar(ctx, 10)
	if err != nil {
		t.Errorf("FindSimilar in passive mode should not return error: %v", err)
	}

	if len(peers) != 0 {
		t.Errorf("FindSimilar in passive mode should return empty, got %d peers", len(peers))
	}
}

func TestFindSimilarNoSignature(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	host, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Close()

	dht, err := NewDHT(ctx, host)
	if err != nil {
		t.Fatalf("NewDHT failed: %v", err)
	}
	defer dht.Close()

	d := NewDiscovery(host, dht)

	// FindSimilar without a signature should return error
	_, err = d.FindSimilar(ctx, 10)
	if err == nil {
		t.Error("FindSimilar without signature should return error")
	}
}

// ============================================================
// Concurrent Operation Tests
// ============================================================

func TestDiscoveryConcurrentOperations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	host1, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost 1 failed: %v", err)
	}
	defer host1.Close()

	host2, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost 2 failed: %v", err)
	}
	defer host2.Close()

	dht1, err := NewDHT(ctx, host1)
	if err != nil {
		t.Fatalf("NewDHT 1 failed: %v", err)
	}
	defer dht1.Close()

	dht2, err := NewDHT(ctx, host2)
	if err != nil {
		t.Fatalf("NewDHT 2 failed: %v", err)
	}
	defer dht2.Close()

	err = host2.Connect(ctx, host1.AddrInfo())
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	err = dht1.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("Bootstrap 1 failed: %v", err)
	}

	err = dht2.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("Bootstrap 2 failed: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	d := NewDiscovery(host1, dht1)
	sig := createTestMonadSignature(t)
	_ = d.UpdateSignature(sig)

	var wg sync.WaitGroup

	// Run concurrent operations
	for i := 0; i < 10; i++ {
		wg.Add(3)

		go func() {
			defer wg.Done()
			d.SetVisibility(VisibilityActive)
			_ = d.Visibility()
		}()

		go func() {
			defer wg.Done()
			newSig := createTestMonadSignature(t)
			_ = d.UpdateSignature(newSig)
		}()

		go func() {
			defer wg.Done()
			_ = d.Signature()
		}()
	}

	wg.Wait()
}

// ============================================================
// Exclude Self Tests
// ============================================================

func TestFindSimilarExcludesSelf(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Need two nodes to form a network for DHT publishing
	host1, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost 1 failed: %v", err)
	}
	defer host1.Close()

	host2, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost 2 failed: %v", err)
	}
	defer host2.Close()

	dht1, err := NewDHT(ctx, host1)
	if err != nil {
		t.Fatalf("NewDHT 1 failed: %v", err)
	}
	defer dht1.Close()

	dht2, err := NewDHT(ctx, host2)
	if err != nil {
		t.Fatalf("NewDHT 2 failed: %v", err)
	}
	defer dht2.Close()

	// Connect nodes
	err = host2.Connect(ctx, host1.AddrInfo())
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	err = dht1.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("Bootstrap 1 failed: %v", err)
	}

	err = dht2.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("Bootstrap 2 failed: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	d := NewDiscovery(host1, dht1)
	sig := createTestMonadSignature(t)
	err = d.UpdateSignature(sig)
	if err != nil {
		t.Fatalf("UpdateSignature failed: %v", err)
	}

	// Publish buckets (self)
	err = d.PublishBuckets(ctx)
	if err != nil {
		t.Fatalf("PublishBuckets failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Find similar should not return self
	peers, err := d.FindSimilar(ctx, 10)
	if err != nil {
		t.Fatalf("FindSimilar failed: %v", err)
	}

	for _, p := range peers {
		if p.ID == host1.ID() {
			t.Error("FindSimilar should not return self")
		}
	}
}

// ============================================================
// Helper Functions
// ============================================================

func createTestMonadSignature(t *testing.T) *lsh.MonadSignature {
	t.Helper()

	// Create a test monad with 64 dimensions
	m := monad.New(64)

	// Initialize with some test vector data via Update
	testVector := make([]float32, 64)
	for i := range testVector {
		testVector[i] = float32(i) / 64.0
	}

	// Use Update to set the vector
	err := m.Update(testVector)
	if err != nil {
		t.Fatalf("Failed to update monad: %v", err)
	}

	// Create generator and generate signature
	gen := lsh.NewGenerator(64, 64, 42)
	sig := gen.Generate(m)

	if sig == nil {
		t.Fatal("Failed to generate test signature")
	}

	return sig
}

// ============================================================
// Deduplication Tests
// ============================================================

func TestFindSimilarDeduplicatesPeers(t *testing.T) {
	// This tests that if a peer is found in multiple buckets,
	// they only appear once in the result
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	host1, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost 1 failed: %v", err)
	}
	defer host1.Close()

	host2, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost 2 failed: %v", err)
	}
	defer host2.Close()

	dht1, err := NewDHT(ctx, host1)
	if err != nil {
		t.Fatalf("NewDHT 1 failed: %v", err)
	}
	defer dht1.Close()

	dht2, err := NewDHT(ctx, host2)
	if err != nil {
		t.Fatalf("NewDHT 2 failed: %v", err)
	}
	defer dht2.Close()

	err = host2.Connect(ctx, host1.AddrInfo())
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	err = dht1.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("Bootstrap 1 failed: %v", err)
	}

	err = dht2.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("Bootstrap 2 failed: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	// Both use same signature to maximize bucket overlap
	d1 := NewDiscovery(host1, dht1)
	d2 := NewDiscovery(host2, dht2)

	sig := createTestMonadSignature(t)
	_ = d1.UpdateSignature(sig)
	_ = d2.UpdateSignature(sig)

	err = d1.PublishBuckets(ctx)
	if err != nil {
		t.Fatalf("PublishBuckets failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	peers, err := d2.FindSimilar(ctx, 10)
	if err != nil {
		t.Fatalf("FindSimilar failed: %v", err)
	}

	// Check for duplicates
	seen := make(map[peer.ID]bool)
	for _, p := range peers {
		if seen[p.ID] {
			t.Errorf("Peer %s appears multiple times in results", p.ID)
		}
		seen[p.ID] = true
	}
}

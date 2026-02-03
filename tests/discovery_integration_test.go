// Package tests contains integration tests for the LSH discovery protocol.
// These tests verify the complete commit-reveal exchange flow between peers.
package tests

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	pb "github.com/mymonad/mymonad/api/proto"
	"github.com/mymonad/mymonad/internal/discovery"
	"github.com/mymonad/mymonad/pkg/lsh"
)

// ===========================================================================
// Test Helpers
// ===========================================================================

// createDiscoveryTestHost creates a libp2p host for discovery testing.
func createDiscoveryTestHost(t *testing.T) host.Host {
	t.Helper()

	h, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.DisableRelay(),
	)
	if err != nil {
		t.Fatalf("failed to create host: %v", err)
	}
	return h
}

// connectDiscoveryHosts connects two libp2p hosts.
func connectDiscoveryHosts(t *testing.T, h1, h2 host.Host) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := h1.Connect(ctx, peer.AddrInfo{
		ID:    h2.ID(),
		Addrs: h2.Addrs(),
	})
	if err != nil {
		t.Fatalf("failed to connect hosts: %v", err)
	}
}

// makeDiscoverySignature creates a random 32-byte LSH signature.
func makeDiscoverySignature(size int) []byte {
	sig := make([]byte, size)
	rand.Read(sig)
	return sig
}

// makeSimilarSignature creates a signature with specified Hamming distance from the original.
// percentDifferent should be 0-100 (e.g., 20 means 20% of bits differ).
func makeSimilarSignature(original []byte, percentDifferent int) []byte {
	result := make([]byte, len(original))
	copy(result, original)

	totalBits := len(original) * 8
	bitsToFlip := (totalBits * percentDifferent) / 100

	// Flip the specified number of bits
	for i := 0; i < bitsToFlip && i < totalBits; i++ {
		byteIdx := i / 8
		bitIdx := uint(i % 8)
		result[byteIdx] ^= (1 << bitIdx)
	}

	return result
}

// makeDiscoverySalt creates a random salt of specified size.
func makeDiscoverySalt(size int) []byte {
	salt := make([]byte, size)
	rand.Read(salt)
	return salt
}

// computeDiscoveryCommitment generates SHA-256(signature || salt).
func computeDiscoveryCommitment(signature, salt []byte) []byte {
	h := sha256.New()
	h.Write(signature)
	h.Write(salt)
	return h.Sum(nil)
}

// computeHammingDistance counts differing bits between two byte slices.
func computeHammingDistance(a, b []byte) int {
	if len(a) != len(b) {
		return -1
	}

	distance := 0
	for i := range a {
		xored := a[i] ^ b[i]
		for xored != 0 {
			distance++
			xored &= xored - 1
		}
	}
	return distance
}

// newTestDiscoveryManager creates a discovery manager with test-friendly config.
func newTestDiscoveryManager(t *testing.T) *discovery.LSHDiscoveryManager {
	t.Helper()
	cfg := discovery.DefaultLSHDiscoveryConfig()
	cfg.InitiationRateLimit = 100 * time.Millisecond // Short for testing
	cfg.ExchangeTimeout = 5 * time.Second
	return discovery.NewLSHDiscoveryManager(cfg)
}

// ===========================================================================
// Full Exchange Flow Test (Alice + Bob)
// ===========================================================================

func TestDiscovery_FullExchangeFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create two discovery managers
	alice := newTestDiscoveryManager(t)
	bob := newTestDiscoveryManager(t)

	// Create similar signatures (20% Hamming distance = 51 bits out of 256)
	aliceSig := makeDiscoverySignature(32) // 256 bits
	bobSig := makeSimilarSignature(aliceSig, 20)

	alice.SetLocalSignature(aliceSig)
	bob.SetLocalSignature(bobSig)

	// Create two libp2p hosts
	aliceHost := createDiscoveryTestHost(t)
	bobHost := createDiscoveryTestHost(t)
	defer aliceHost.Close()
	defer bobHost.Close()

	// Connect hosts
	connectDiscoveryHosts(t, aliceHost, bobHost)

	// Determine who initiates (lower peer ID)
	aliceInitiates := aliceHost.ID() < bobHost.ID()

	// Create pipe-based streams for testing
	aliceReader, bobWriter := io.Pipe()
	bobReader, aliceWriter := io.Pipe()

	var wg sync.WaitGroup
	var aliceErr, bobErr error
	var alicePeerSig, bobPeerSig []byte

	// Alice's exchange
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer aliceWriter.Close()

		exchange, err := alice.AddPendingExchange(bobHost.ID(), discovery.RoleInitiator)
		if err != nil {
			aliceErr = err
			return
		}

		if aliceInitiates {
			// Alice sends commit first
			aliceErr = runInitiatorExchange(aliceReader, aliceWriter, exchange, &alicePeerSig)
		} else {
			// Alice receives commit first
			aliceErr = runResponderExchange(aliceReader, aliceWriter, exchange, &alicePeerSig)
		}
	}()

	// Bob's exchange
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer bobWriter.Close()

		exchange, err := bob.AddPendingExchange(aliceHost.ID(), discovery.RoleResponder)
		if err != nil {
			bobErr = err
			return
		}

		if aliceInitiates {
			// Bob receives commit first
			bobErr = runResponderExchange(bobReader, bobWriter, exchange, &bobPeerSig)
		} else {
			// Bob sends commit first
			bobErr = runInitiatorExchange(bobReader, bobWriter, exchange, &bobPeerSig)
		}
	}()

	wg.Wait()

	// Check for errors
	if aliceErr != nil {
		t.Fatalf("Alice exchange failed: %v", aliceErr)
	}
	if bobErr != nil {
		t.Fatalf("Bob exchange failed: %v", bobErr)
	}

	// Verify Alice got Bob's signature and vice versa
	if !bytes.Equal(alicePeerSig, bobSig) {
		t.Error("Alice did not receive Bob's correct signature")
	}
	if !bytes.Equal(bobPeerSig, aliceSig) {
		t.Error("Bob did not receive Alice's correct signature")
	}

	// Verify Hamming distance is within threshold (25% of 256 = 64)
	hammingDist := computeHammingDistance(aliceSig, bobSig)
	threshold := alice.Config().HammingThreshold // 64 by default

	if hammingDist > threshold {
		t.Errorf("Hamming distance %d exceeds threshold %d", hammingDist, threshold)
	}

	t.Logf("Exchange successful: Hamming distance = %d (threshold = %d)", hammingDist, threshold)
}

// runInitiatorExchange runs the commit-reveal protocol as initiator.
func runInitiatorExchange(r io.Reader, w io.Writer, ex *discovery.Exchange, peerSig *[]byte) error {
	// Send our commit
	commit := &pb.DiscoveryCommit{
		Commitment: ex.Commitment,
		Timestamp:  time.Now().UnixMilli(),
		PeerId:     []byte(ex.PeerID),
	}
	if err := discovery.WriteCommit(w, commit); err != nil {
		return err
	}
	ex.State = discovery.ExchangeStateCommitSent

	// Receive peer's commit
	peerCommit, err := discovery.ReadCommit(r)
	if err != nil {
		return err
	}
	ex.SetPeerCommitment(peerCommit.Commitment)
	ex.State = discovery.ExchangeStateCommitReceived

	// Send our reveal
	reveal := &pb.DiscoveryReveal{
		Signature: ex.SignatureSnapshot,
		Salt:      ex.Salt,
	}
	if err := discovery.WriteReveal(w, reveal); err != nil {
		return err
	}
	ex.State = discovery.ExchangeStateRevealSent

	// Receive peer's reveal
	peerReveal, err := discovery.ReadReveal(r)
	if err != nil {
		return err
	}

	// Verify peer's commitment
	if err := ex.SetPeerReveal(peerReveal.Signature, peerReveal.Salt); err != nil {
		return err
	}

	*peerSig = peerReveal.Signature
	ex.State = discovery.ExchangeStateComplete
	return nil
}

// runResponderExchange runs the commit-reveal protocol as responder.
func runResponderExchange(r io.Reader, w io.Writer, ex *discovery.Exchange, peerSig *[]byte) error {
	// Receive peer's commit first
	peerCommit, err := discovery.ReadCommit(r)
	if err != nil {
		return err
	}
	ex.SetPeerCommitment(peerCommit.Commitment)
	ex.State = discovery.ExchangeStateCommitReceived

	// Send our commit
	commit := &pb.DiscoveryCommit{
		Commitment: ex.Commitment,
		Timestamp:  time.Now().UnixMilli(),
		PeerId:     []byte(ex.PeerID),
	}
	if err := discovery.WriteCommit(w, commit); err != nil {
		return err
	}
	ex.State = discovery.ExchangeStateCommitSent

	// Receive peer's reveal
	peerReveal, err := discovery.ReadReveal(r)
	if err != nil {
		return err
	}

	// Verify peer's commitment before sending our reveal
	if err := ex.SetPeerReveal(peerReveal.Signature, peerReveal.Salt); err != nil {
		return err
	}

	// Send our reveal
	reveal := &pb.DiscoveryReveal{
		Signature: ex.SignatureSnapshot,
		Salt:      ex.Salt,
	}
	if err := discovery.WriteReveal(w, reveal); err != nil {
		return err
	}

	*peerSig = peerReveal.Signature
	ex.State = discovery.ExchangeStateComplete
	return nil
}

// ===========================================================================
// Adversarial Test (Mallory tampered reveal)
// ===========================================================================

func TestDiscovery_RejectMaliciousPeer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	alice := newTestDiscoveryManager(t)
	mallory := newTestDiscoveryManager(t) // Malicious peer

	aliceSig := makeDiscoverySignature(32)
	mallorySig := makeDiscoverySignature(32)       // Signature Mallory will commit to
	tamperedSig := makeDiscoverySignature(32)      // Different signature Mallory will reveal
	mallorySalt := makeDiscoverySalt(16)

	alice.SetLocalSignature(aliceSig)
	mallory.SetLocalSignature(mallorySig)

	// Compute Mallory's valid commitment (to original signature)
	malloryCommitment := computeDiscoveryCommitment(mallorySig, mallorySalt)

	// Create exchanges
	aliceExchange, err := alice.AddPendingExchange(peer.ID("mallory"), discovery.RoleResponder)
	if err != nil {
		t.Fatalf("failed to create Alice exchange: %v", err)
	}

	// Simulate exchange via pipes
	aliceReader, malloryWriter := io.Pipe()
	malloryReader, aliceWriter := io.Pipe()

	var wg sync.WaitGroup
	var aliceErr error
	var malloryErr error

	// Alice (responder)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer aliceWriter.Close()

		// Receive Mallory's commit
		peerCommit, err := discovery.ReadCommit(aliceReader)
		if err != nil {
			aliceErr = err
			return
		}
		aliceExchange.SetPeerCommitment(peerCommit.Commitment)

		// Send Alice's commit
		commit := &pb.DiscoveryCommit{
			Commitment: aliceExchange.Commitment,
			Timestamp:  time.Now().UnixMilli(),
			PeerId:     []byte("alice"),
		}
		if err := discovery.WriteCommit(aliceWriter, commit); err != nil {
			aliceErr = err
			return
		}

		// Receive Mallory's reveal (tampered!)
		peerReveal, err := discovery.ReadReveal(aliceReader)
		if err != nil {
			aliceErr = err
			return
		}

		// This should fail because Mallory sent a different signature
		aliceErr = aliceExchange.SetPeerReveal(peerReveal.Signature, peerReveal.Salt)
	}()

	// Mallory (initiator, malicious)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer malloryWriter.Close()

		// Send valid commitment (to mallorySig)
		commit := &pb.DiscoveryCommit{
			Commitment: malloryCommitment,
			Timestamp:  time.Now().UnixMilli(),
			PeerId:     []byte("mallory"),
		}
		if err := discovery.WriteCommit(malloryWriter, commit); err != nil {
			malloryErr = err
			return
		}

		// Receive Alice's commit
		_, err := discovery.ReadCommit(malloryReader)
		if err != nil {
			malloryErr = err
			return
		}

		// Send TAMPERED reveal (different signature than committed!)
		tamperedReveal := &pb.DiscoveryReveal{
			Signature: tamperedSig,  // Different from mallorySig!
			Salt:      mallorySalt,
		}
		if err := discovery.WriteReveal(malloryWriter, tamperedReveal); err != nil {
			malloryErr = err
			return
		}
	}()

	wg.Wait()

	// Mallory's side should complete without error (just sending data)
	if malloryErr != nil {
		t.Logf("Mallory encountered error (expected if Alice closed stream): %v", malloryErr)
	}

	// Alice should detect the commitment mismatch
	if aliceErr == nil {
		t.Fatal("Alice should have detected commitment mismatch")
	}

	// Verify it's the right error type
	if aliceErr.Error() != "commitment_mismatch" {
		t.Errorf("Expected commitment_mismatch error, got: %v", aliceErr)
	}

	// Verify exchange state is failed
	if aliceExchange.State != discovery.ExchangeStateFailed {
		t.Errorf("Expected ExchangeStateFailed, got: %v", aliceExchange.State)
	}

	t.Log("Successfully detected and rejected malicious peer with tampered reveal")
}

// ===========================================================================
// DHT Partition Test
// ===========================================================================

func TestDiscovery_DHTPartitionContinuesWithBucketPeers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create a discovery manager with existing discovered peers
	dm := newTestDiscoveryManager(t)
	dm.SetLocalSignature(makeDiscoverySignature(32))

	// Pre-populate with discovered peers (simulating previous DHT queries)
	existingPeer1 := peer.ID("existing-peer-1")
	existingPeer2 := peer.ID("existing-peer-2")

	dm.AddDiscoveredPeer(existingPeer1, makeDiscoverySignature(32), 30)
	dm.AddDiscoveredPeer(existingPeer2, makeDiscoverySignature(32), 45)

	// Verify peers exist
	if dm.GetDiscoveredPeerCount() != 2 {
		t.Fatalf("Expected 2 discovered peers, got %d", dm.GetDiscoveredPeerCount())
	}

	// Simulate DHT failure by not having a real DHT
	// The manager should still be able to list and work with existing peers

	peers := dm.ListDiscoveredPeers()
	if len(peers) != 2 {
		t.Fatalf("Expected 2 peers after simulated DHT failure, got %d", len(peers))
	}

	// Verify peers are within threshold and can be used for exchanges
	for _, p := range peers {
		if !dm.IsWithinThreshold(p.HammingDistance) {
			t.Errorf("Peer %s has Hamming distance %d exceeding threshold", p.PeerID, p.HammingDistance)
		}
	}

	// Verify we can still initiate exchanges with existing peers
	exchange, err := dm.AddPendingExchange(existingPeer1, discovery.RoleInitiator)
	if err != nil {
		t.Fatalf("Failed to initiate exchange with existing peer: %v", err)
	}

	if exchange.PeerID != existingPeer1 {
		t.Errorf("Exchange peer ID mismatch: expected %s, got %s", existingPeer1, exchange.PeerID)
	}

	t.Log("DHT partition handled: continuing with existing bucket peers")
}

// TestDiscovery_SignatureStateRepublish tests the republish logic for DHT records.
func TestDiscovery_SignatureStateRepublish(t *testing.T) {
	// Test SignatureState.ShouldRepublish with different scenarios
	state := &discovery.SignatureState{}

	// Never published - should republish
	if !state.ShouldRepublish() {
		t.Error("Expected ShouldRepublish=true when never published")
	}

	// Just published - should not republish
	state.MarkPublished()
	if state.ShouldRepublish() {
		t.Error("Expected ShouldRepublish=false immediately after publishing")
	}

	// Simulate time passing past republish buffer (55 minutes for 1 hour TTL with 5 min buffer)
	state.PublishedAt = time.Now().Add(-56 * time.Minute)
	if !state.ShouldRepublish() {
		t.Error("Expected ShouldRepublish=true after TTL-buffer period")
	}
}

// ===========================================================================
// Concurrent Exchange Test
// ===========================================================================

func TestDiscovery_ConcurrentExchanges(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := discovery.DefaultLSHDiscoveryConfig()
	cfg.MaxPendingExchanges = 5
	cfg.InitiationRateLimit = 10 * time.Millisecond
	dm := discovery.NewLSHDiscoveryManager(cfg)
	dm.SetLocalSignature(makeDiscoverySignature(32))

	var wg sync.WaitGroup
	var successCount atomic.Int32
	var errorCount atomic.Int32
	numConcurrent := 10

	// Launch concurrent exchanges
	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			peerID := peer.ID([]byte{byte(idx)})
			_, err := dm.AddPendingExchange(peerID, discovery.RoleInitiator)
			if err != nil {
				errorCount.Add(1)
			} else {
				successCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	// Verify MaxPendingExchanges limit is enforced
	success := int(successCount.Load())
	errors := int(errorCount.Load())

	if success > cfg.MaxPendingExchanges {
		t.Errorf("MaxPendingExchanges limit violated: %d successful (max: %d)", success, cfg.MaxPendingExchanges)
	}

	if success+errors != numConcurrent {
		t.Errorf("Expected %d total attempts, got %d success + %d errors", numConcurrent, success, errors)
	}

	// At least some should succeed
	if success == 0 {
		t.Error("Expected at least some exchanges to succeed")
	}

	// At least some should fail due to limit
	if errors == 0 && numConcurrent > cfg.MaxPendingExchanges {
		t.Error("Expected some exchanges to fail due to MaxPendingExchanges limit")
	}

	t.Logf("Concurrent exchanges: %d succeeded, %d failed (limit: %d)", success, errors, cfg.MaxPendingExchanges)
}

// TestDiscovery_ConcurrentExchangesNoInterference verifies exchanges don't interfere.
func TestDiscovery_ConcurrentExchangesNoInterference(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := discovery.DefaultLSHDiscoveryConfig()
	cfg.MaxPendingExchanges = 10
	dm := discovery.NewLSHDiscoveryManager(cfg)
	dm.SetLocalSignature(makeDiscoverySignature(32))

	numExchanges := 5
	exchanges := make([]*discovery.Exchange, numExchanges)

	// Create multiple exchanges
	for i := 0; i < numExchanges; i++ {
		peerID := peer.ID([]byte{byte(i + 100)})
		ex, err := dm.AddPendingExchange(peerID, discovery.RoleInitiator)
		if err != nil {
			t.Fatalf("Failed to create exchange %d: %v", i, err)
		}
		exchanges[i] = ex
	}

	// Verify each exchange has unique commitment and salt
	commitments := make(map[string]int)
	salts := make(map[string]int)

	for i, ex := range exchanges {
		commitKey := string(ex.Commitment)
		saltKey := string(ex.Salt)

		if prev, exists := commitments[commitKey]; exists {
			t.Errorf("Duplicate commitment between exchange %d and %d", prev, i)
		}
		commitments[commitKey] = i

		if prev, exists := salts[saltKey]; exists {
			t.Errorf("Duplicate salt between exchange %d and %d", prev, i)
		}
		salts[saltKey] = i
	}

	// Verify each exchange has same signature snapshot (from manager)
	localSig := dm.GetLocalSignature()
	for i, ex := range exchanges {
		if !bytes.Equal(ex.SignatureSnapshot, localSig) {
			t.Errorf("Exchange %d has different signature snapshot", i)
		}
	}

	// Verify each exchange can be retrieved by its peer ID
	for i, ex := range exchanges {
		retrieved := dm.GetPendingExchange(ex.PeerID)
		if retrieved == nil {
			t.Errorf("Failed to retrieve exchange %d by peer ID", i)
			continue
		}
		if retrieved != ex {
			t.Errorf("Retrieved exchange %d is not the same instance", i)
		}
	}

	t.Log("Concurrent exchanges do not interfere with each other")
}

// ===========================================================================
// Bucket Derivation Integration
// ===========================================================================

func TestDiscovery_BucketDerivationConsistency(t *testing.T) {
	// Test that similar signatures derive to the same or nearby buckets
	sig1 := makeDiscoverySignature(32)
	sig2 := makeSimilarSignature(sig1, 10) // 10% different

	bucket1 := lsh.DeriveBucketID(sig1)
	bucket2 := lsh.DeriveBucketID(sig2)

	// Log the buckets for informational purposes
	t.Logf("Signature 1 bucket: %s", bucket1)
	t.Logf("Signature 2 bucket: %s", bucket2)

	// The bucket ID is derived from the first byte, so similar signatures
	// MAY or MAY NOT have the same bucket depending on the first byte
	// This is expected behavior - we just verify derivation works

	if bucket1 == "" {
		t.Error("Empty bucket ID for signature 1")
	}
	if bucket2 == "" {
		t.Error("Empty bucket ID for signature 2")
	}

	// Empty signature should return empty bucket
	emptyBucket := lsh.DeriveBucketID(nil)
	if emptyBucket != "" {
		t.Errorf("Expected empty bucket for nil signature, got: %s", emptyBucket)
	}
}

// ===========================================================================
// Stream-Based Integration Test
// ===========================================================================

func TestDiscovery_StreamProtocolIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create two hosts
	host1 := createDiscoveryTestHost(t)
	host2 := createDiscoveryTestHost(t)
	defer host1.Close()
	defer host2.Close()

	// Create discovery managers
	dm1 := newTestDiscoveryManager(t)
	dm2 := newTestDiscoveryManager(t)

	sig1 := makeDiscoverySignature(32)
	sig2 := makeSimilarSignature(sig1, 15)

	dm1.SetLocalSignature(sig1)
	dm2.SetLocalSignature(sig2)

	// Track exchange completion
	var exchangeComplete atomic.Bool
	var host2ReceivedSig []byte
	var mu sync.Mutex

	// Set up host2's stream handler
	host2.SetStreamHandler(protocol.ID(discovery.ProtocolID), func(s network.Stream) {
		defer s.Close()

		// Create exchange for this peer
		exchange, err := dm2.AddPendingExchange(s.Conn().RemotePeer(), discovery.RoleResponder)
		if err != nil {
			t.Logf("Host2 failed to create exchange: %v", err)
			return
		}

		// Receive commit
		peerCommit, err := discovery.ReadCommit(s)
		if err != nil {
			t.Logf("Host2 failed to read commit: %v", err)
			return
		}
		exchange.SetPeerCommitment(peerCommit.Commitment)

		// Send our commit
		commit := &pb.DiscoveryCommit{
			Commitment: exchange.Commitment,
			Timestamp:  time.Now().UnixMilli(),
			PeerId:     []byte(host2.ID()),
		}
		if err := discovery.WriteCommit(s, commit); err != nil {
			t.Logf("Host2 failed to write commit: %v", err)
			return
		}

		// Receive reveal
		peerReveal, err := discovery.ReadReveal(s)
		if err != nil {
			t.Logf("Host2 failed to read reveal: %v", err)
			return
		}

		// Verify and store
		if err := exchange.SetPeerReveal(peerReveal.Signature, peerReveal.Salt); err != nil {
			t.Logf("Host2 commitment verification failed: %v", err)
			return
		}

		// Send our reveal
		reveal := &pb.DiscoveryReveal{
			Signature: exchange.SignatureSnapshot,
			Salt:      exchange.Salt,
		}
		if err := discovery.WriteReveal(s, reveal); err != nil {
			t.Logf("Host2 failed to write reveal: %v", err)
			return
		}

		mu.Lock()
		host2ReceivedSig = peerReveal.Signature
		mu.Unlock()
		exchangeComplete.Store(true)
	})

	// Connect hosts
	connectDiscoveryHosts(t, host1, host2)

	// Host1 initiates exchange
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := host1.NewStream(ctx, host2.ID(), protocol.ID(discovery.ProtocolID))
	if err != nil {
		t.Fatalf("Failed to open stream: %v", err)
	}
	defer stream.Close()

	exchange, err := dm1.AddPendingExchange(host2.ID(), discovery.RoleInitiator)
	if err != nil {
		t.Fatalf("Failed to create exchange: %v", err)
	}

	// Send commit
	commit := &pb.DiscoveryCommit{
		Commitment: exchange.Commitment,
		Timestamp:  time.Now().UnixMilli(),
		PeerId:     []byte(host1.ID()),
	}
	if err := discovery.WriteCommit(stream, commit); err != nil {
		t.Fatalf("Failed to write commit: %v", err)
	}

	// Receive commit
	peerCommit, err := discovery.ReadCommit(stream)
	if err != nil {
		t.Fatalf("Failed to read commit: %v", err)
	}
	exchange.SetPeerCommitment(peerCommit.Commitment)

	// Send reveal
	reveal := &pb.DiscoveryReveal{
		Signature: exchange.SignatureSnapshot,
		Salt:      exchange.Salt,
	}
	if err := discovery.WriteReveal(stream, reveal); err != nil {
		t.Fatalf("Failed to write reveal: %v", err)
	}

	// Receive reveal
	peerReveal, err := discovery.ReadReveal(stream)
	if err != nil {
		t.Fatalf("Failed to read reveal: %v", err)
	}

	// Verify
	if err := exchange.SetPeerReveal(peerReveal.Signature, peerReveal.Salt); err != nil {
		t.Fatalf("Commitment verification failed: %v", err)
	}

	// Wait for host2 to complete
	deadline := time.After(5 * time.Second)
	for !exchangeComplete.Load() {
		select {
		case <-deadline:
			t.Fatal("Timeout waiting for exchange completion")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Verify both sides got correct signatures
	if !bytes.Equal(peerReveal.Signature, sig2) {
		t.Error("Host1 did not receive correct signature from Host2")
	}

	mu.Lock()
	if !bytes.Equal(host2ReceivedSig, sig1) {
		t.Error("Host2 did not receive correct signature from Host1")
	}
	mu.Unlock()

	t.Log("Stream protocol integration test passed")
}

// ===========================================================================
// Edge Cases and Error Handling
// ===========================================================================

func TestDiscovery_ExchangeExpiration(t *testing.T) {
	dm := newTestDiscoveryManager(t)
	dm.SetLocalSignature(makeDiscoverySignature(32))

	peerID := peer.ID("test-peer")
	ex, err := dm.AddPendingExchange(peerID, discovery.RoleInitiator)
	if err != nil {
		t.Fatalf("Failed to create exchange: %v", err)
	}

	// Exchange should not be expired initially
	if ex.IsExpired() {
		t.Error("Exchange should not be expired immediately")
	}

	// Manually set expiry to past (the ExchangeTimeout constant is 30s, so we
	// simulate expiration by directly setting ExpiresAt to the past)
	ex.ExpiresAt = time.Now().Add(-time.Second)

	// Exchange should now be expired
	if !ex.IsExpired() {
		t.Error("Exchange should be expired when ExpiresAt is in the past")
	}

	// Cleanup should remove expired exchanges
	removed := dm.CleanupExpiredExchanges()
	if removed != 1 {
		t.Errorf("Expected 1 expired exchange removed, got %d", removed)
	}

	// Should be gone from pending exchanges
	if dm.GetPendingExchange(peerID) != nil {
		t.Error("Expired exchange should be removed from pending")
	}
}

func TestDiscovery_RejectMalformedSignature(t *testing.T) {
	dm := newTestDiscoveryManager(t)
	dm.SetLocalSignature(makeDiscoverySignature(32))

	ex, err := dm.AddPendingExchange(peer.ID("test"), discovery.RoleResponder)
	if err != nil {
		t.Fatalf("Failed to create exchange: %v", err)
	}

	// Simulate receiving a malformed signature (wrong length)
	shortSig := makeDiscoverySignature(16) // Should be 32 bytes
	salt := makeDiscoverySalt(16)
	commitment := computeDiscoveryCommitment(shortSig, salt)

	ex.SetPeerCommitment(commitment)
	err = ex.SetPeerReveal(shortSig, salt)

	if err == nil {
		t.Error("Expected error for malformed signature")
	}
	if err.Error() != "malformed_signature" {
		t.Errorf("Expected malformed_signature error, got: %v", err)
	}
	if ex.State != discovery.ExchangeStateFailed {
		t.Errorf("Expected ExchangeStateFailed, got: %v", ex.State)
	}
}

func TestDiscovery_RejectInvalidSalt(t *testing.T) {
	dm := newTestDiscoveryManager(t)
	dm.SetLocalSignature(makeDiscoverySignature(32))

	ex, err := dm.AddPendingExchange(peer.ID("test"), discovery.RoleResponder)
	if err != nil {
		t.Fatalf("Failed to create exchange: %v", err)
	}

	// Simulate receiving an invalid salt (too short)
	sig := makeDiscoverySignature(32)
	shortSalt := makeDiscoverySalt(8) // Should be 16+ bytes
	commitment := computeDiscoveryCommitment(sig, shortSalt)

	ex.SetPeerCommitment(commitment)
	err = ex.SetPeerReveal(sig, shortSalt)

	if err == nil {
		t.Error("Expected error for invalid salt")
	}
	if err.Error() != "invalid_salt" {
		t.Errorf("Expected invalid_salt error, got: %v", err)
	}
	if ex.State != discovery.ExchangeStateFailed {
		t.Errorf("Expected ExchangeStateFailed, got: %v", ex.State)
	}
}

// ===========================================================================
// Benchmarks
// ===========================================================================

func BenchmarkDiscovery_ExchangeCreation(b *testing.B) {
	dm := discovery.NewLSHDiscoveryManager(discovery.DefaultLSHDiscoveryConfig())
	dm.SetLocalSignature(makeDiscoverySignature(32))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		peerID := peer.ID([]byte{byte(i % 256)})
		dm.AddPendingExchange(peerID, discovery.RoleInitiator)
		dm.RemovePendingExchange(peerID)
	}
}

func BenchmarkDiscovery_CommitmentVerification(b *testing.B) {
	sig := makeDiscoverySignature(32)
	salt := makeDiscoverySalt(16)
	commitment := computeDiscoveryCommitment(sig, salt)

	dm := discovery.NewLSHDiscoveryManager(discovery.DefaultLSHDiscoveryConfig())
	dm.SetLocalSignature(makeDiscoverySignature(32))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ex, _ := dm.AddPendingExchange(peer.ID("test"), discovery.RoleResponder)
		ex.SetPeerCommitment(commitment)
		ex.SetPeerReveal(sig, salt)
		dm.RemovePendingExchange(peer.ID("test"))
	}
}

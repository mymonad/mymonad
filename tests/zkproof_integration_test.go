// Package tests contains integration tests for the ZK proof system.
// These tests verify the complete ZK proof exchange flow between two peers,
// including proof generation, verification, and stream-based exchanges.
package tests

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mymonad/mymonad/internal/zkproof"
	pkgzkproof "github.com/mymonad/mymonad/pkg/zkproof"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Test Helpers
// ===========================================================================

// makeSignature creates a random 256-bit (32-byte) signature.
func makeSignature(bits int) []byte {
	sig := make([]byte, bits/8)
	_, err := rand.Read(sig)
	if err != nil {
		panic(err)
	}
	return sig
}

// makeZKSimilarSignature creates a signature with specified Hamming distance from original.
// It flips exactly 'distance' random bits to achieve the desired Hamming distance.
// This is different from makeSimilarSignature which uses percentage-based distance.
func makeZKSimilarSignature(original []byte, distance int) []byte {
	result := make([]byte, len(original))
	copy(result, original)

	// Flip 'distance' random bits
	flipped := make(map[int]bool)
	totalBits := len(original) * 8

	for len(flipped) < distance {
		// Generate random bit position
		buf := make([]byte, 2)
		_, _ = rand.Read(buf)
		bitPos := int(buf[0])<<8 | int(buf[1])
		bitPos = bitPos % totalBits

		if !flipped[bitPos] {
			flipped[bitPos] = true
			byteIdx := bitPos / 8
			bitIdx := uint(bitPos % 8)
			result[byteIdx] ^= (1 << bitIdx)
		}
	}

	return result
}

// createZKService creates an enabled ZK service for testing.
// This compiles the circuit, which takes a few seconds.
func createZKService(t *testing.T) *zkproof.ZKService {
	t.Helper()

	cfg := zkproof.DefaultZKConfig()
	cfg.Enabled = true
	cfg.ProofTimeout = 60 * time.Second
	cfg.MaxDistance = 64

	svc, err := zkproof.NewZKService(cfg)
	require.NoError(t, err, "failed to create ZK service")
	require.True(t, svc.IsEnabled(), "ZK service should be enabled")

	return svc
}

// mockStream implements zkproof.StreamReadWriter for testing stream exchanges.
type mockStream struct {
	reader       io.Reader
	writer       io.Writer
	readDeadline time.Time
}

func (m *mockStream) Read(p []byte) (n int, err error) {
	return m.reader.Read(p)
}

func (m *mockStream) Write(p []byte) (n int, err error) {
	return m.writer.Write(p)
}

func (m *mockStream) SetReadDeadline(t time.Time) error {
	m.readDeadline = t
	return nil
}

// createPipeStreams creates a pair of connected mock streams for testing.
func createPipeStreams() (*mockStream, *mockStream) {
	// Create two pipes for bidirectional communication
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	// Alice writes to w1, Bob reads from r1
	// Bob writes to w2, Alice reads from r2
	aliceStream := &mockStream{reader: r2, writer: w1}
	bobStream := &mockStream{reader: r1, writer: w2}

	return aliceStream, bobStream
}

// ===========================================================================
// Integration Tests
// ===========================================================================

// TestZKProof_FullExchange tests a complete ZK proof exchange between two peers.
// Both peers prove their signatures are within the Hamming distance threshold.
func TestZKProof_FullExchange(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ZK proof integration test in short mode (requires circuit compilation)")
	}

	// Setup two ZK-enabled services (shares compiled circuit via cache)
	t.Log("Setting up ZK services (this may take a few seconds for circuit compilation)...")
	alice := createZKService(t)
	bob := createZKService(t)

	// Create similar signatures (Hamming distance < 64)
	t.Log("Creating test signatures with Hamming distance = 20...")
	aliceSig := makeSignature(256)
	bobSig := makeZKSimilarSignature(aliceSig, 20) // 20 bits different

	// Verify actual Hamming distance
	distance, err := pkgzkproof.HammingDistanceBytes(aliceSig, bobSig)
	require.NoError(t, err)
	require.Equal(t, 20, distance, "expected Hamming distance of 20")
	t.Logf("Actual Hamming distance between signatures: %d", distance)

	// Alice generates proof
	t.Log("Alice generating proof...")
	aliceProof, err := alice.GetProver().GenerateProof(aliceSig, bobSig, 64)
	require.NoError(t, err, "Alice failed to generate proof")
	require.NotNil(t, aliceProof)
	require.NotEmpty(t, aliceProof.Proof)
	require.NotEmpty(t, aliceProof.Commitment)

	// Bob verifies Alice's proof
	t.Log("Bob verifying Alice's proof...")
	err = bob.GetVerifier().VerifyProof(
		aliceProof.Proof,
		aliceProof.Commitment,
		bobSig, // Bob uses his own signature as the peer signature
		64,
	)
	require.NoError(t, err, "Bob failed to verify Alice's proof")

	// Bob generates proof
	t.Log("Bob generating proof...")
	bobProof, err := bob.GetProver().GenerateProof(bobSig, aliceSig, 64)
	require.NoError(t, err, "Bob failed to generate proof")
	require.NotNil(t, bobProof)
	require.NotEmpty(t, bobProof.Proof)
	require.NotEmpty(t, bobProof.Commitment)

	// Alice verifies Bob's proof
	t.Log("Alice verifying Bob's proof...")
	err = alice.GetVerifier().VerifyProof(
		bobProof.Proof,
		bobProof.Commitment,
		aliceSig, // Alice uses her own signature as the peer signature
		64,
	)
	require.NoError(t, err, "Alice failed to verify Bob's proof")

	t.Log("Full ZK proof exchange completed successfully!")

	// Verify metrics
	aliceGen, aliceVer, aliceFail := alice.Stats()
	t.Logf("Alice stats - generated: %d, verified: %d, failed: %d", aliceGen, aliceVer, aliceFail)

	bobGen, bobVer, bobFail := bob.Stats()
	t.Logf("Bob stats - generated: %d, verified: %d, failed: %d", bobGen, bobVer, bobFail)
}

// TestZKProof_RejectsDissimilarPeers verifies that proof generation fails
// when signatures are too different (exceed the Hamming distance threshold).
func TestZKProof_RejectsDissimilarPeers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ZK proof integration test in short mode (requires circuit compilation)")
	}

	t.Log("Setting up ZK service...")
	svc := createZKService(t)

	// Create very different signatures (Hamming distance > 64)
	t.Log("Creating dissimilar signatures with Hamming distance = 150...")
	sigA := makeSignature(256)
	sigB := makeZKSimilarSignature(sigA, 150) // 150 bits different

	// Verify actual Hamming distance
	distance, err := pkgzkproof.HammingDistanceBytes(sigA, sigB)
	require.NoError(t, err)
	require.Equal(t, 150, distance, "expected Hamming distance of 150")
	t.Logf("Actual Hamming distance: %d (threshold: 64)", distance)

	// Proof generation should fail because distance exceeds threshold
	t.Log("Attempting to generate proof (should fail)...")
	_, err = svc.GetProver().GenerateProof(sigA, sigB, 64)
	require.Error(t, err, "proof generation should fail for dissimilar signatures")
	require.Contains(t, err.Error(), "threshold",
		"error should mention threshold exceeded")
	t.Logf("Proof generation correctly failed: %v", err)
}

// TestZKProof_StreamExchange tests a full ZK exchange over in-memory pipe streams.
// This simulates the actual network protocol flow.
func TestZKProof_StreamExchange(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ZK proof integration test in short mode (requires circuit compilation)")
	}

	t.Log("Setting up ZK services...")
	aliceSvc := createZKService(t)
	bobSvc := createZKService(t)

	// Create similar signatures
	t.Log("Creating test signatures...")
	aliceSig := makeSignature(256)
	bobSig := makeZKSimilarSignature(aliceSig, 30) // 30 bits different

	// Create pipe streams for communication
	aliceStream, bobStream := createPipeStreams()

	// Create exchanges
	aliceCfg := aliceSvc.GetConfig()
	bobCfg := bobSvc.GetConfig()

	// Create prover/verifier adapters that implement the exchange interfaces
	aliceExchange := zkproof.NewZKExchange(
		&proverAdapter{prover: aliceSvc.GetProver()},
		&verifierAdapter{verifier: aliceSvc.GetVerifier()},
		aliceCfg,
	)
	bobExchange := zkproof.NewZKExchange(
		&proverAdapter{prover: bobSvc.GetProver()},
		&verifierAdapter{verifier: bobSvc.GetVerifier()},
		bobCfg,
	)

	// Run exchange in parallel
	var wg sync.WaitGroup
	var aliceErr, bobErr error

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Alice initiates
	wg.Add(1)
	go func() {
		defer wg.Done()
		t.Log("Alice initiating exchange...")
		aliceErr = aliceExchange.InitiateExchange(ctx, aliceStream, aliceSig, bobSig)
		if aliceErr != nil {
			t.Logf("Alice exchange error: %v", aliceErr)
		}
	}()

	// Bob handles
	wg.Add(1)
	go func() {
		defer wg.Done()
		t.Log("Bob handling exchange...")
		bobErr = bobExchange.HandleExchange(ctx, bobStream, bobSig)
		if bobErr != nil {
			t.Logf("Bob exchange error: %v", bobErr)
		}
	}()

	wg.Wait()

	require.NoError(t, aliceErr, "Alice exchange should succeed")
	require.NoError(t, bobErr, "Bob exchange should succeed")

	t.Log("Stream-based ZK exchange completed successfully!")
}

// TestZKProof_StreamExchangeFailsForDissimilarPeers verifies that a stream exchange
// fails when peers have dissimilar signatures.
// Note: This test uses net.Pipe with timeouts to avoid hanging when proof generation fails.
func TestZKProof_StreamExchangeFailsForDissimilarPeers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ZK proof integration test in short mode (requires circuit compilation)")
	}

	t.Log("Setting up ZK services...")
	aliceSvc := createZKService(t)
	bobSvc := createZKService(t)

	// Create very different signatures (distance > threshold)
	t.Log("Creating dissimilar signatures...")
	aliceSig := makeSignature(256)
	bobSig := makeZKSimilarSignature(aliceSig, 100) // 100 bits different, threshold is 64

	// Use net.Pipe so we can close it properly and handle failures
	aliceConn, bobConn := net.Pipe()

	// Create exchanges
	aliceCfg := aliceSvc.GetConfig()
	aliceCfg.ProofTimeout = 5 * time.Second // Short timeout for failure detection
	bobCfg := bobSvc.GetConfig()
	bobCfg.ProofTimeout = 5 * time.Second

	aliceExchange := zkproof.NewZKExchange(
		&proverAdapter{prover: aliceSvc.GetProver()},
		&verifierAdapter{verifier: aliceSvc.GetVerifier()},
		aliceCfg,
	)
	bobExchange := zkproof.NewZKExchange(
		&proverAdapter{prover: bobSvc.GetProver()},
		&verifierAdapter{verifier: bobSvc.GetVerifier()},
		bobCfg,
	)

	// Run exchange in parallel with proper cleanup
	resultCh := make(chan struct {
		name string
		err  error
	}, 2)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		aliceStream := &netConnStream{conn: aliceConn}
		err := aliceExchange.InitiateExchange(ctx, aliceStream, aliceSig, bobSig)
		resultCh <- struct {
			name string
			err  error
		}{"Alice", err}
		aliceConn.Close() // Close pipe on completion/error
	}()

	go func() {
		bobStream := &netConnStream{conn: bobConn}
		err := bobExchange.HandleExchange(ctx, bobStream, bobSig)
		resultCh <- struct {
			name string
			err  error
		}{"Bob", err}
		bobConn.Close() // Close pipe on completion/error
	}()

	// Wait for both results with timeout
	var results []struct {
		name string
		err  error
	}
	timeout := time.After(15 * time.Second)

	for i := 0; i < 2; i++ {
		select {
		case r := <-resultCh:
			results = append(results, r)
		case <-timeout:
			t.Fatal("test timeout waiting for exchange results")
		}
	}

	// At least one side should fail (proof generation fails due to distance)
	failed := false
	for _, r := range results {
		if r.err != nil {
			failed = true
			t.Logf("%s error: %v", r.name, r.err)
		}
	}
	require.True(t, failed, "exchange should fail for dissimilar signatures")
	t.Log("Exchange correctly failed as expected!")
}

// TestZKCapability_Compatibility tests the ZK capability compatibility checking.
func TestZKCapability_Compatibility(t *testing.T) {
	t.Run("compatible capability", func(t *testing.T) {
		compatible := &zkproof.ZKCapability{
			Supported:        true,
			ProofSystem:      zkproof.SupportedProofSystem,
			MaxSignatureBits: zkproof.SupportedSignatureBits,
		}
		err := zkproof.CheckCompatibility(compatible)
		require.NoError(t, err, "compatible capability should pass")
	})

	t.Run("incompatible proof system", func(t *testing.T) {
		incompatible := &zkproof.ZKCapability{
			Supported:        true,
			ProofSystem:      "groth16-bn254", // Wrong system
			MaxSignatureBits: zkproof.SupportedSignatureBits,
		}
		err := zkproof.CheckCompatibility(incompatible)
		require.Error(t, err, "incompatible proof system should fail")
		require.Contains(t, err.Error(), "groth16-bn254")
	})

	t.Run("incompatible signature bits", func(t *testing.T) {
		incompatible := &zkproof.ZKCapability{
			Supported:        true,
			ProofSystem:      zkproof.SupportedProofSystem,
			MaxSignatureBits: 512, // Wrong size
		}
		err := zkproof.CheckCompatibility(incompatible)
		require.Error(t, err, "incompatible signature bits should fail")
		require.Contains(t, err.Error(), "512")
	})

	t.Run("ZK not supported", func(t *testing.T) {
		notSupported := &zkproof.ZKCapability{
			Supported:        false,
			ProofSystem:      zkproof.SupportedProofSystem,
			MaxSignatureBits: zkproof.SupportedSignatureBits,
		}
		err := zkproof.CheckCompatibility(notSupported)
		require.Error(t, err, "unsupported ZK should fail")
	})

	t.Run("nil capability", func(t *testing.T) {
		err := zkproof.CheckCompatibility(nil)
		require.Error(t, err, "nil capability should fail")
	})
}

// TestZKProof_ServiceMetrics verifies that the ZK service correctly tracks metrics.
func TestZKProof_ServiceMetrics(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ZK proof integration test in short mode")
	}

	svc := createZKService(t)

	// Initial stats should be zero
	gen, ver, fail := svc.Stats()
	require.Equal(t, uint64(0), gen)
	require.Equal(t, uint64(0), ver)
	require.Equal(t, uint64(0), fail)

	// Record some metrics
	svc.RecordProofGenerated()
	svc.RecordProofGenerated()
	svc.RecordProofVerified()
	svc.RecordProofFailed()

	gen, ver, fail = svc.Stats()
	require.Equal(t, uint64(2), gen, "generated count should be 2")
	require.Equal(t, uint64(1), ver, "verified count should be 1")
	require.Equal(t, uint64(1), fail, "failed count should be 1")
}

// TestZKProof_DisabledService verifies behavior when ZK is disabled.
func TestZKProof_DisabledService(t *testing.T) {
	cfg := zkproof.DefaultZKConfig()
	cfg.Enabled = false

	svc, err := zkproof.NewZKService(cfg)
	require.NoError(t, err)
	require.False(t, svc.IsEnabled(), "service should not be enabled")
	require.Nil(t, svc.GetProver(), "prover should be nil when disabled")
	require.Nil(t, svc.GetVerifier(), "verifier should be nil when disabled")
}

// TestZKProof_BoundaryDistances tests proof generation at boundary conditions.
func TestZKProof_BoundaryDistances(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ZK proof integration test in short mode")
	}

	svc := createZKService(t)

	tests := []struct {
		name        string
		distance    int
		threshold   uint32
		shouldPass  bool
	}{
		{"exact threshold", 64, 64, true},
		{"one below threshold", 63, 64, true},
		{"one above threshold", 65, 64, false},
		{"zero distance", 0, 64, true},
		{"minimum threshold exceeded", 1, 0, false},
		{"minimum threshold met", 0, 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sigA := makeSignature(256)
			sigB := makeZKSimilarSignature(sigA, tc.distance)

			// Verify actual distance
			actualDist, err := pkgzkproof.HammingDistanceBytes(sigA, sigB)
			require.NoError(t, err)
			require.Equal(t, tc.distance, actualDist)

			_, err = svc.GetProver().GenerateProof(sigA, sigB, tc.threshold)
			if tc.shouldPass {
				require.NoError(t, err, "proof generation should succeed for %s", tc.name)
			} else {
				require.Error(t, err, "proof generation should fail for %s", tc.name)
			}
		})
	}
}

// TestZKProof_ConcurrentProofGeneration tests that multiple proofs can be generated concurrently.
func TestZKProof_ConcurrentProofGeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ZK proof integration test in short mode")
	}

	svc := createZKService(t)

	const numProofs = 3
	var wg sync.WaitGroup
	errors := make(chan error, numProofs)

	for i := 0; i < numProofs; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			sigA := makeSignature(256)
			sigB := makeZKSimilarSignature(sigA, 30)

			_, err := svc.GetProver().GenerateProof(sigA, sigB, 64)
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent proof generation failed: %v", err)
	}
}

// TestZKProof_FullExchangeWithNetPipe tests exchange over net.Pipe connections.
// This is closer to real network conditions than io.Pipe.
func TestZKProof_FullExchangeWithNetPipe(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ZK proof integration test in short mode")
	}

	t.Log("Setting up ZK services...")
	aliceSvc := createZKService(t)
	bobSvc := createZKService(t)

	// Create similar signatures
	aliceSig := makeSignature(256)
	bobSig := makeZKSimilarSignature(aliceSig, 25)

	// Use net.Pipe for more realistic simulation
	aliceConn, bobConn := net.Pipe()
	defer aliceConn.Close()
	defer bobConn.Close()

	// Wrap net.Conn in mockStream (they implement io.Reader/Writer)
	aliceStream := &netConnStream{conn: aliceConn}
	bobStream := &netConnStream{conn: bobConn}

	// Create exchanges
	aliceCfg := aliceSvc.GetConfig()
	bobCfg := bobSvc.GetConfig()

	aliceExchange := zkproof.NewZKExchange(
		&proverAdapter{prover: aliceSvc.GetProver()},
		&verifierAdapter{verifier: aliceSvc.GetVerifier()},
		aliceCfg,
	)
	bobExchange := zkproof.NewZKExchange(
		&proverAdapter{prover: bobSvc.GetProver()},
		&verifierAdapter{verifier: bobSvc.GetVerifier()},
		bobCfg,
	)

	var wg sync.WaitGroup
	var aliceErr, bobErr error

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	wg.Add(2)
	go func() {
		defer wg.Done()
		aliceErr = aliceExchange.InitiateExchange(ctx, aliceStream, aliceSig, bobSig)
	}()

	go func() {
		defer wg.Done()
		bobErr = bobExchange.HandleExchange(ctx, bobStream, bobSig)
	}()

	wg.Wait()

	require.NoError(t, aliceErr, "Alice exchange should succeed")
	require.NoError(t, bobErr, "Bob exchange should succeed")

	t.Log("net.Pipe ZK exchange completed successfully!")
}

// ===========================================================================
// Adapters and Helpers
// ===========================================================================

// proverAdapter adapts pkg/zkproof.Prover to internal/zkproof.ProverInterface.
type proverAdapter struct {
	prover *pkgzkproof.Prover
}

func (a *proverAdapter) GenerateProof(mySignature, peerSignature []byte, maxDistance uint32) (*zkproof.ProofResult, error) {
	result, err := a.prover.GenerateProof(mySignature, peerSignature, maxDistance)
	if err != nil {
		return nil, err
	}
	return &zkproof.ProofResult{
		Proof:      result.Proof,
		Commitment: result.Commitment,
	}, nil
}

// verifierAdapter adapts pkg/zkproof.Verifier to internal/zkproof.VerifierInterface.
type verifierAdapter struct {
	verifier *pkgzkproof.Verifier
}

func (a *verifierAdapter) VerifyProof(proofBytes, proverCommitment, peerSignature []byte, maxDistance uint32) error {
	return a.verifier.VerifyProof(proofBytes, proverCommitment, peerSignature, maxDistance)
}

// netConnStream wraps net.Conn to implement zkproof.StreamReadWriter.
type netConnStream struct {
	conn net.Conn
}

func (s *netConnStream) Read(p []byte) (n int, err error) {
	return s.conn.Read(p)
}

func (s *netConnStream) Write(p []byte) (n int, err error) {
	return s.conn.Write(p)
}

func (s *netConnStream) SetReadDeadline(t time.Time) error {
	return s.conn.SetReadDeadline(t)
}

// ===========================================================================
// Benchmark Tests
// ===========================================================================

func BenchmarkZKProof_ProofGeneration(b *testing.B) {
	cfg := zkproof.DefaultZKConfig()
	cfg.Enabled = true
	cfg.MaxDistance = 64

	svc, err := zkproof.NewZKService(cfg)
	if err != nil {
		b.Fatalf("failed to create ZK service: %v", err)
	}

	sigA := makeSignature(256)
	sigB := makeZKSimilarSignature(sigA, 30)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := svc.GetProver().GenerateProof(sigA, sigB, 64)
		if err != nil {
			b.Fatalf("proof generation failed: %v", err)
		}
	}
}

func BenchmarkZKProof_ProofVerification(b *testing.B) {
	cfg := zkproof.DefaultZKConfig()
	cfg.Enabled = true
	cfg.MaxDistance = 64

	svc, err := zkproof.NewZKService(cfg)
	if err != nil {
		b.Fatalf("failed to create ZK service: %v", err)
	}

	sigA := makeSignature(256)
	sigB := makeZKSimilarSignature(sigA, 30)

	// Generate proof once
	proof, err := svc.GetProver().GenerateProof(sigA, sigB, 64)
	if err != nil {
		b.Fatalf("proof generation failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := svc.GetVerifier().VerifyProof(proof.Proof, proof.Commitment, sigB, 64)
		if err != nil {
			b.Fatalf("proof verification failed: %v", err)
		}
	}
}

func BenchmarkZKProof_HammingDistance(b *testing.B) {
	sigA := makeSignature(256)
	sigB := makeZKSimilarSignature(sigA, 50)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pkgzkproof.HammingDistanceBytes(sigA, sigB)
	}
}

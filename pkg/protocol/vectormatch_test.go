// Package protocol implements the MyMonad handshake protocol for agent matching.
package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// ============================================================================
// VectorMatchRequest Tests
// ============================================================================

func TestNewVectorMatchRequest(t *testing.T) {
	peerID := generateTestPeerID(t)
	encryptedMonad := []byte("encrypted-monad-data")

	t.Run("creates valid request", func(t *testing.T) {
		req := NewVectorMatchRequest(peerID, encryptedMonad)

		if req == nil {
			t.Fatal("expected non-nil request")
		}
		if req.PeerID != peerID {
			t.Errorf("expected peerID %v, got %v", peerID, req.PeerID)
		}
		if string(req.EncryptedMonad) != string(encryptedMonad) {
			t.Errorf("expected encryptedMonad %v, got %v", encryptedMonad, req.EncryptedMonad)
		}
		if req.Timestamp.IsZero() {
			t.Error("expected non-zero timestamp")
		}
		// Signature should be nil before signing
		if req.Signature != nil {
			t.Error("expected nil signature before Sign()")
		}
	})

	t.Run("timestamp is recent", func(t *testing.T) {
		req := NewVectorMatchRequest(peerID, encryptedMonad)

		if time.Since(req.Timestamp) > time.Second {
			t.Errorf("timestamp should be recent, got %v", req.Timestamp)
		}
	})

	t.Run("handles empty encrypted monad", func(t *testing.T) {
		req := NewVectorMatchRequest(peerID, []byte{})

		if req == nil {
			t.Fatal("expected non-nil request even with empty monad")
		}
		if len(req.EncryptedMonad) != 0 {
			t.Error("expected empty encrypted monad")
		}
	})

	t.Run("handles nil encrypted monad", func(t *testing.T) {
		req := NewVectorMatchRequest(peerID, nil)

		if req == nil {
			t.Fatal("expected non-nil request even with nil monad")
		}
	})
}

func TestVectorMatchRequestSign(t *testing.T) {
	peerID := generateTestPeerID(t)
	_, priv := generateTestKeyPair(t)
	encryptedMonad := []byte("encrypted-monad-data")

	t.Run("signs request successfully", func(t *testing.T) {
		req := NewVectorMatchRequest(peerID, encryptedMonad)

		err := req.Sign(priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(req.Signature) != ed25519.SignatureSize {
			t.Errorf("expected signature length %d, got %d", ed25519.SignatureSize, len(req.Signature))
		}
	})

	t.Run("signature is deterministic for same content", func(t *testing.T) {
		req := NewVectorMatchRequest(peerID, encryptedMonad)

		err := req.Sign(priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sig1 := make([]byte, len(req.Signature))
		copy(sig1, req.Signature)

		// Sign again with same key
		req.Signature = nil
		err = req.Sign(priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if string(req.Signature) != string(sig1) {
			t.Error("signature should be deterministic for same content")
		}
	})
}

func TestVectorMatchRequestVerify(t *testing.T) {
	peerID := generateTestPeerID(t)
	pub, priv := generateTestKeyPair(t)
	pub2, _ := generateTestKeyPair(t)
	encryptedMonad := []byte("encrypted-monad-data")

	t.Run("verifies valid signature", func(t *testing.T) {
		req := NewVectorMatchRequest(peerID, encryptedMonad)
		_ = req.Sign(priv)

		err := req.Verify(pub)
		if err != nil {
			t.Fatalf("expected valid signature, got error: %v", err)
		}
	})

	t.Run("rejects invalid signature", func(t *testing.T) {
		req := NewVectorMatchRequest(peerID, encryptedMonad)
		_ = req.Sign(priv)

		err := req.Verify(pub2)
		if err == nil {
			t.Error("expected error for invalid signature")
		}
	})

	t.Run("rejects tampered request - peer ID", func(t *testing.T) {
		req := NewVectorMatchRequest(peerID, encryptedMonad)
		_ = req.Sign(priv)

		req.PeerID = peer.ID("12D3KooWTamperedPeerID")

		err := req.Verify(pub)
		if err == nil {
			t.Error("expected error for tampered peer ID")
		}
	})

	t.Run("rejects tampered request - encrypted monad", func(t *testing.T) {
		req := NewVectorMatchRequest(peerID, encryptedMonad)
		_ = req.Sign(priv)

		req.EncryptedMonad = []byte("tampered-monad-data")

		err := req.Verify(pub)
		if err == nil {
			t.Error("expected error for tampered encrypted monad")
		}
	})

	t.Run("rejects unsigned request", func(t *testing.T) {
		req := NewVectorMatchRequest(peerID, encryptedMonad)

		err := req.Verify(pub)
		if err == nil {
			t.Error("expected error for unsigned request")
		}
	})
}

func TestVectorMatchRequestBytesToSign(t *testing.T) {
	peerID := generateTestPeerID(t)
	encryptedMonad := []byte("encrypted-monad-data")

	req := NewVectorMatchRequest(peerID, encryptedMonad)

	t.Run("returns consistent bytes", func(t *testing.T) {
		bytes1 := req.BytesToSign()
		bytes2 := req.BytesToSign()

		if string(bytes1) != string(bytes2) {
			t.Error("BytesToSign should return consistent results")
		}

		if len(bytes1) == 0 {
			t.Error("BytesToSign should return non-empty bytes")
		}
	})

	t.Run("different requests produce different bytes", func(t *testing.T) {
		req2 := NewVectorMatchRequest(peerID, []byte("different-monad"))

		bytes1 := req.BytesToSign()
		bytes2 := req2.BytesToSign()

		if string(bytes1) == string(bytes2) {
			t.Error("different requests should produce different bytes")
		}
	})
}

// ============================================================================
// VectorMatchResponse Tests
// ============================================================================

func TestNewVectorMatchResponse(t *testing.T) {
	peerID := generateTestPeerID(t)

	t.Run("creates response with matched=true when score >= threshold", func(t *testing.T) {
		resp := NewVectorMatchResponse(peerID, 0.85, 0.7)

		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if resp.PeerID != peerID {
			t.Errorf("expected peerID %v, got %v", peerID, resp.PeerID)
		}
		if resp.Score != 0.85 {
			t.Errorf("expected score 0.85, got %v", resp.Score)
		}
		if !resp.Matched {
			t.Error("expected matched=true when score >= threshold")
		}
		if resp.Timestamp.IsZero() {
			t.Error("expected non-zero timestamp")
		}
	})

	t.Run("creates response with matched=false when score < threshold", func(t *testing.T) {
		resp := NewVectorMatchResponse(peerID, 0.5, 0.7)

		if resp.Matched {
			t.Error("expected matched=false when score < threshold")
		}
	})

	t.Run("matched=true when score equals threshold", func(t *testing.T) {
		resp := NewVectorMatchResponse(peerID, 0.7, 0.7)

		if !resp.Matched {
			t.Error("expected matched=true when score == threshold")
		}
	})

	t.Run("handles edge case scores", func(t *testing.T) {
		// Score of 1.0 (maximum)
		resp1 := NewVectorMatchResponse(peerID, 1.0, 0.7)
		if !resp1.Matched {
			t.Error("expected matched=true for score 1.0")
		}

		// Score of 0.0 (minimum for normalized)
		resp2 := NewVectorMatchResponse(peerID, 0.0, 0.7)
		if resp2.Matched {
			t.Error("expected matched=false for score 0.0")
		}

		// Negative score (possible with non-normalized vectors)
		resp3 := NewVectorMatchResponse(peerID, -0.5, 0.0)
		if resp3.Matched {
			t.Error("expected matched=false for negative score with threshold 0")
		}
	})

	t.Run("timestamp is recent", func(t *testing.T) {
		resp := NewVectorMatchResponse(peerID, 0.8, 0.7)

		if time.Since(resp.Timestamp) > time.Second {
			t.Errorf("timestamp should be recent, got %v", resp.Timestamp)
		}
	})
}

func TestVectorMatchResponseSign(t *testing.T) {
	peerID := generateTestPeerID(t)
	_, priv := generateTestKeyPair(t)

	t.Run("signs response successfully", func(t *testing.T) {
		resp := NewVectorMatchResponse(peerID, 0.85, 0.7)

		err := resp.Sign(priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(resp.Signature) != ed25519.SignatureSize {
			t.Errorf("expected signature length %d, got %d", ed25519.SignatureSize, len(resp.Signature))
		}
	})
}

func TestVectorMatchResponseVerify(t *testing.T) {
	peerID := generateTestPeerID(t)
	pub, priv := generateTestKeyPair(t)
	pub2, _ := generateTestKeyPair(t)

	t.Run("verifies valid signature", func(t *testing.T) {
		resp := NewVectorMatchResponse(peerID, 0.85, 0.7)
		_ = resp.Sign(priv)

		err := resp.Verify(pub)
		if err != nil {
			t.Fatalf("expected valid signature, got error: %v", err)
		}
	})

	t.Run("rejects invalid signature", func(t *testing.T) {
		resp := NewVectorMatchResponse(peerID, 0.85, 0.7)
		_ = resp.Sign(priv)

		err := resp.Verify(pub2)
		if err == nil {
			t.Error("expected error for invalid signature")
		}
	})

	t.Run("rejects tampered response - score", func(t *testing.T) {
		resp := NewVectorMatchResponse(peerID, 0.85, 0.7)
		_ = resp.Sign(priv)

		resp.Score = 0.99

		err := resp.Verify(pub)
		if err == nil {
			t.Error("expected error for tampered score")
		}
	})

	t.Run("rejects tampered response - matched", func(t *testing.T) {
		resp := NewVectorMatchResponse(peerID, 0.5, 0.7) // matched=false
		_ = resp.Sign(priv)

		resp.Matched = true // tamper

		err := resp.Verify(pub)
		if err == nil {
			t.Error("expected error for tampered matched field")
		}
	})

	t.Run("rejects unsigned response", func(t *testing.T) {
		resp := NewVectorMatchResponse(peerID, 0.85, 0.7)

		err := resp.Verify(pub)
		if err == nil {
			t.Error("expected error for unsigned response")
		}
	})
}

func TestVectorMatchResponseBytesToSign(t *testing.T) {
	peerID := generateTestPeerID(t)

	resp := NewVectorMatchResponse(peerID, 0.85, 0.7)

	t.Run("returns consistent bytes", func(t *testing.T) {
		bytes1 := resp.BytesToSign()
		bytes2 := resp.BytesToSign()

		if string(bytes1) != string(bytes2) {
			t.Error("BytesToSign should return consistent results")
		}

		if len(bytes1) == 0 {
			t.Error("BytesToSign should return non-empty bytes")
		}
	})

	t.Run("different responses produce different bytes", func(t *testing.T) {
		resp2 := NewVectorMatchResponse(peerID, 0.5, 0.7)

		bytes1 := resp.BytesToSign()
		bytes2 := resp2.BytesToSign()

		if string(bytes1) == string(bytes2) {
			t.Error("different responses should produce different bytes")
		}
	})
}

// ============================================================================
// MockTEE Tests
// ============================================================================

func TestMockTEEComputeSimilarity(t *testing.T) {
	tee := NewMockTEE()

	t.Run("computes similarity for identical vectors", func(t *testing.T) {
		// Create two identical vectors (3 dimensions for simplicity)
		vec := []float32{0.5, 0.5, 0.5}
		monadA := encodeVector(vec)
		monadB := encodeVector(vec)

		score, err := tee.ComputeSimilarity(monadA, monadB)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Identical vectors should have similarity ~1.0
		if score < 0.99 {
			t.Errorf("expected similarity ~1.0 for identical vectors, got %v", score)
		}
	})

	t.Run("computes similarity for orthogonal vectors", func(t *testing.T) {
		// Create two orthogonal vectors
		vecA := []float32{1.0, 0.0, 0.0}
		vecB := []float32{0.0, 1.0, 0.0}
		monadA := encodeVector(vecA)
		monadB := encodeVector(vecB)

		score, err := tee.ComputeSimilarity(monadA, monadB)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Orthogonal vectors should have similarity ~0.0
		if math.Abs(float64(score)) > 0.01 {
			t.Errorf("expected similarity ~0.0 for orthogonal vectors, got %v", score)
		}
	})

	t.Run("computes similarity for opposite vectors", func(t *testing.T) {
		// Create two opposite vectors
		vecA := []float32{1.0, 0.0, 0.0}
		vecB := []float32{-1.0, 0.0, 0.0}
		monadA := encodeVector(vecA)
		monadB := encodeVector(vecB)

		score, err := tee.ComputeSimilarity(monadA, monadB)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Opposite vectors should have similarity ~-1.0
		if score > -0.99 {
			t.Errorf("expected similarity ~-1.0 for opposite vectors, got %v", score)
		}
	})

	t.Run("computes similarity for similar vectors", func(t *testing.T) {
		// Create two similar but not identical vectors
		vecA := []float32{0.8, 0.5, 0.2}
		vecB := []float32{0.7, 0.6, 0.3}
		monadA := encodeVector(vecA)
		monadB := encodeVector(vecB)

		score, err := tee.ComputeSimilarity(monadA, monadB)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Similar vectors should have high positive similarity
		if score < 0.9 || score > 1.0 {
			t.Errorf("expected high similarity for similar vectors, got %v", score)
		}
	})

	t.Run("returns error for dimension mismatch", func(t *testing.T) {
		vecA := []float32{1.0, 0.0, 0.0}
		vecB := []float32{1.0, 0.0}
		monadA := encodeVector(vecA)
		monadB := encodeVector(vecB)

		_, err := tee.ComputeSimilarity(monadA, monadB)
		if err == nil {
			t.Error("expected error for dimension mismatch")
		}
	})

	t.Run("returns error for invalid monad data", func(t *testing.T) {
		// Invalid data that can't be decoded
		_, err := tee.ComputeSimilarity([]byte("invalid"), []byte("invalid"))
		if err == nil {
			t.Error("expected error for invalid monad data")
		}
	})

	t.Run("handles zero vectors", func(t *testing.T) {
		vecA := []float32{0.0, 0.0, 0.0}
		vecB := []float32{1.0, 0.0, 0.0}
		monadA := encodeVector(vecA)
		monadB := encodeVector(vecB)

		score, err := tee.ComputeSimilarity(monadA, monadB)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Zero vector similarity should be 0
		if score != 0.0 {
			t.Errorf("expected 0.0 for zero vector, got %v", score)
		}
	})
}

func TestMockTEEConcurrency(t *testing.T) {
	tee := NewMockTEE()

	var wg sync.WaitGroup
	numGoroutines := 50
	errors := make([]error, numGoroutines)
	scores := make([]float32, numGoroutines)

	vecA := []float32{0.5, 0.5, 0.5}
	vecB := []float32{0.4, 0.6, 0.5}
	monadA := encodeVector(vecA)
	monadB := encodeVector(vecB)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			score, err := tee.ComputeSimilarity(monadA, monadB)
			errors[idx] = err
			scores[idx] = score
		}(i)
	}

	wg.Wait()

	// All computations should succeed and produce same result
	var expectedScore float32
	for i := 0; i < numGoroutines; i++ {
		if errors[i] != nil {
			t.Errorf("computation %d failed: %v", i, errors[i])
			continue
		}
		if i == 0 {
			expectedScore = scores[i]
		} else if scores[i] != expectedScore {
			t.Errorf("computation %d produced different score: expected %v, got %v", i, expectedScore, scores[i])
		}
	}
}

// ============================================================================
// Integration Tests
// ============================================================================

func TestVectorMatchFlow(t *testing.T) {
	// Simulate a full vector match flow
	initiatorPeerID := peer.ID("12D3KooWInitiator123456789")
	responderPeerID := peer.ID("12D3KooWResponder123456789")
	initiatorPub, initiatorPriv := generateTestKeyPair(t)
	responderPub, responderPriv := generateTestKeyPair(t)
	threshold := float32(0.7)

	// Create mock encrypted monads (in reality these would be TEE-encrypted)
	initiatorMonad := encodeVector([]float32{0.8, 0.5, 0.2})
	responderMonad := encodeVector([]float32{0.7, 0.6, 0.3})

	// Step 1: Initiator creates and signs a request
	req := NewVectorMatchRequest(initiatorPeerID, initiatorMonad)
	if err := req.Sign(initiatorPriv); err != nil {
		t.Fatalf("failed to sign request: %v", err)
	}

	// Step 2: Responder verifies the request
	if err := req.Verify(initiatorPub); err != nil {
		t.Fatalf("failed to verify request: %v", err)
	}

	// Step 3: Mock TEE computes similarity
	tee := NewMockTEE()
	score, err := tee.ComputeSimilarity(req.EncryptedMonad, responderMonad)
	if err != nil {
		t.Fatalf("failed to compute similarity: %v", err)
	}

	// Step 4: Responder creates and signs a response
	resp := NewVectorMatchResponse(responderPeerID, score, threshold)
	if err := resp.Sign(responderPriv); err != nil {
		t.Fatalf("failed to sign response: %v", err)
	}

	// Step 5: Initiator verifies the response
	if err := resp.Verify(responderPub); err != nil {
		t.Fatalf("failed to verify response: %v", err)
	}

	// Verify the match result is sensible
	if score < 0.9 || score > 1.0 {
		t.Errorf("expected high score for similar vectors, got %v", score)
	}
	if !resp.Matched {
		t.Error("expected matched=true for high similarity")
	}
}

func TestVectorMatchFlowNoMatch(t *testing.T) {
	// Simulate a vector match flow that doesn't result in a match
	initiatorPeerID := peer.ID("12D3KooWInitiator123456789")
	responderPeerID := peer.ID("12D3KooWResponder123456789")
	_, initiatorPriv := generateTestKeyPair(t)
	_, responderPriv := generateTestKeyPair(t)
	threshold := float32(0.9) // High threshold

	// Create dissimilar monads
	initiatorMonad := encodeVector([]float32{1.0, 0.0, 0.0})
	responderMonad := encodeVector([]float32{0.0, 1.0, 0.0})

	// Step 1: Initiator creates and signs a request
	req := NewVectorMatchRequest(initiatorPeerID, initiatorMonad)
	_ = req.Sign(initiatorPriv)

	// Step 2: Mock TEE computes similarity
	tee := NewMockTEE()
	score, err := tee.ComputeSimilarity(req.EncryptedMonad, responderMonad)
	if err != nil {
		t.Fatalf("failed to compute similarity: %v", err)
	}

	// Step 3: Responder creates response
	resp := NewVectorMatchResponse(responderPeerID, score, threshold)
	_ = resp.Sign(responderPriv)

	// Verify no match for orthogonal vectors
	if resp.Matched {
		t.Error("expected matched=false for orthogonal vectors with high threshold")
	}
}

func TestVectorMatchConcurrentRequests(t *testing.T) {
	peerID := generateTestPeerID(t)
	encryptedMonad := []byte("encrypted-monad-data")

	var wg sync.WaitGroup
	numGoroutines := 10
	requests := make([]*VectorMatchRequest, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			requests[idx] = NewVectorMatchRequest(peerID, encryptedMonad)
		}(i)
	}

	wg.Wait()

	// All requests should be created successfully
	for i, req := range requests {
		if req == nil {
			t.Errorf("request %d is nil", i)
		}
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

// encodeVector encodes a float32 vector to bytes (simple format for MockTEE).
// Format: [num_dims as uint32][float32...]
func encodeVector(vec []float32) []byte {
	buf := make([]byte, 4+len(vec)*4)
	// Write number of dimensions
	buf[0] = byte(len(vec) >> 24)
	buf[1] = byte(len(vec) >> 16)
	buf[2] = byte(len(vec) >> 8)
	buf[3] = byte(len(vec))
	// Write float32 values
	for i, v := range vec {
		bits := math.Float32bits(v)
		offset := 4 + i*4
		buf[offset] = byte(bits >> 24)
		buf[offset+1] = byte(bits >> 16)
		buf[offset+2] = byte(bits >> 8)
		buf[offset+3] = byte(bits)
	}
	return buf
}

// Helper to generate test key pair (uses the one from attestation_test.go if not defined)
func init() {
	// Ensure rand is seeded
	_ = rand.Reader
}

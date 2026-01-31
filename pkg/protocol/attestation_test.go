// Package protocol implements the MyMonad handshake protocol for agent matching.
package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// Helper function to generate a test Ed25519 key pair.
func generateTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	return pub, priv
}

// Helper function to create a test peer ID.
func generateTestPeerID(t *testing.T) peer.ID {
	t.Helper()
	// Create a mock peer ID for testing
	return peer.ID("12D3KooWTestPeerID123456789")
}

// ============================================================================
// AttestationRequest Tests
// ============================================================================

func TestNewAttestationRequest(t *testing.T) {
	peerID := generateTestPeerID(t)
	version := "1.0.0"
	difficulty := 8 // Low difficulty for fast tests

	t.Run("creates valid request with challenge", func(t *testing.T) {
		req, err := NewAttestationRequest(peerID, version, difficulty)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if req == nil {
			t.Fatal("expected non-nil request")
		}
		if req.Version != version {
			t.Errorf("expected version %q, got %q", version, req.Version)
		}
		if req.PeerID != peerID {
			t.Errorf("expected peerID %v, got %v", peerID, req.PeerID)
		}
		if req.Challenge == "" {
			t.Error("expected non-empty challenge")
		}
		if req.Timestamp.IsZero() {
			t.Error("expected non-zero timestamp")
		}
		// Signature should be nil before signing
		if req.Signature != nil {
			t.Error("expected nil signature before Sign()")
		}
	})

	t.Run("challenge is valid hashcash format", func(t *testing.T) {
		req, err := NewAttestationRequest(peerID, version, difficulty)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Hashcash format: version:bits:timestamp:resource:rand
		parts := strings.Split(req.Challenge, ":")
		if len(parts) < 5 {
			t.Errorf("challenge should have at least 5 parts, got %d", len(parts))
		}
	})

	t.Run("each request has unique challenge", func(t *testing.T) {
		req1, _ := NewAttestationRequest(peerID, version, difficulty)
		req2, _ := NewAttestationRequest(peerID, version, difficulty)

		if req1.Challenge == req2.Challenge {
			t.Error("two requests should have different challenges")
		}
	})

	t.Run("timestamp is recent", func(t *testing.T) {
		req, _ := NewAttestationRequest(peerID, version, difficulty)

		if time.Since(req.Timestamp) > time.Second {
			t.Errorf("timestamp should be recent, got %v", req.Timestamp)
		}
	})

	t.Run("invalid difficulty returns error", func(t *testing.T) {
		_, err := NewAttestationRequest(peerID, version, 0)
		if err == nil {
			t.Error("expected error for zero difficulty")
		}

		_, err = NewAttestationRequest(peerID, version, -1)
		if err == nil {
			t.Error("expected error for negative difficulty")
		}
	})
}

func TestAttestationRequestSign(t *testing.T) {
	peerID := generateTestPeerID(t)
	_, priv := generateTestKeyPair(t)
	version := "1.0.0"

	t.Run("signs request successfully", func(t *testing.T) {
		req, _ := NewAttestationRequest(peerID, version, 8)

		err := req.Sign(priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(req.Signature) != ed25519.SignatureSize {
			t.Errorf("expected signature length %d, got %d", ed25519.SignatureSize, len(req.Signature))
		}
	})

	t.Run("signature is deterministic for same content", func(t *testing.T) {
		req, _ := NewAttestationRequest(peerID, version, 8)

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

func TestAttestationRequestVerify(t *testing.T) {
	peerID := generateTestPeerID(t)
	pub, priv := generateTestKeyPair(t)
	pub2, _ := generateTestKeyPair(t) // Different key pair
	version := "1.0.0"

	t.Run("verifies valid signature", func(t *testing.T) {
		req, _ := NewAttestationRequest(peerID, version, 8)
		_ = req.Sign(priv)

		err := req.Verify(pub)
		if err != nil {
			t.Fatalf("expected valid signature, got error: %v", err)
		}
	})

	t.Run("rejects invalid signature", func(t *testing.T) {
		req, _ := NewAttestationRequest(peerID, version, 8)
		_ = req.Sign(priv)

		// Verify with different key
		err := req.Verify(pub2)
		if err == nil {
			t.Error("expected error for invalid signature")
		}
	})

	t.Run("rejects tampered request", func(t *testing.T) {
		req, _ := NewAttestationRequest(peerID, version, 8)
		_ = req.Sign(priv)

		// Tamper with version
		req.Version = "2.0.0"

		err := req.Verify(pub)
		if err == nil {
			t.Error("expected error for tampered request")
		}
	})

	t.Run("rejects unsigned request", func(t *testing.T) {
		req, _ := NewAttestationRequest(peerID, version, 8)

		err := req.Verify(pub)
		if err == nil {
			t.Error("expected error for unsigned request")
		}
	})
}

// ============================================================================
// AttestationResponse Tests
// ============================================================================

func TestNewAttestationResponse(t *testing.T) {
	peerID := generateTestPeerID(t)
	version := "1.0.0"
	// Create a valid challenge with low difficulty for fast tests
	challenge := "1:8:1706745600:test-resource:MTIzNDU2"

	t.Run("creates valid response with solved challenge", func(t *testing.T) {
		resp, err := NewAttestationResponse(peerID, version, challenge)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if resp.Version != version {
			t.Errorf("expected version %q, got %q", version, resp.Version)
		}
		if resp.PeerID != peerID {
			t.Errorf("expected peerID %v, got %v", peerID, resp.PeerID)
		}
		if resp.Solution == "" {
			t.Error("expected non-empty solution")
		}
		if resp.Timestamp.IsZero() {
			t.Error("expected non-zero timestamp")
		}
		// Signature should be nil before signing
		if resp.Signature != nil {
			t.Error("expected nil signature before Sign()")
		}
	})

	t.Run("solution contains counter suffix", func(t *testing.T) {
		resp, err := NewAttestationResponse(peerID, version, challenge)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Solution should be challenge + ":" + counter
		if !strings.HasPrefix(resp.Solution, challenge) {
			t.Errorf("solution should start with challenge, got %q", resp.Solution)
		}

		// Should have counter appended
		parts := strings.Split(resp.Solution, ":")
		if len(parts) <= 5 {
			t.Error("solution should have counter appended")
		}
	})

	t.Run("invalid challenge returns error", func(t *testing.T) {
		_, err := NewAttestationResponse(peerID, version, "invalid-challenge")
		if err == nil {
			t.Error("expected error for invalid challenge")
		}

		_, err = NewAttestationResponse(peerID, version, "")
		if err == nil {
			t.Error("expected error for empty challenge")
		}
	})
}

func TestAttestationResponseSign(t *testing.T) {
	peerID := generateTestPeerID(t)
	_, priv := generateTestKeyPair(t)
	version := "1.0.0"
	challenge := "1:8:1706745600:test-resource:MTIzNDU2"

	t.Run("signs response successfully", func(t *testing.T) {
		resp, _ := NewAttestationResponse(peerID, version, challenge)

		err := resp.Sign(priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(resp.Signature) != ed25519.SignatureSize {
			t.Errorf("expected signature length %d, got %d", ed25519.SignatureSize, len(resp.Signature))
		}
	})
}

func TestAttestationResponseVerify(t *testing.T) {
	peerID := generateTestPeerID(t)
	pub, priv := generateTestKeyPair(t)
	pub2, _ := generateTestKeyPair(t)
	version := "1.0.0"
	challenge := "1:8:1706745600:test-resource:MTIzNDU2"

	t.Run("verifies valid signature", func(t *testing.T) {
		resp, _ := NewAttestationResponse(peerID, version, challenge)
		_ = resp.Sign(priv)

		err := resp.Verify(pub)
		if err != nil {
			t.Fatalf("expected valid signature, got error: %v", err)
		}
	})

	t.Run("rejects invalid signature", func(t *testing.T) {
		resp, _ := NewAttestationResponse(peerID, version, challenge)
		_ = resp.Sign(priv)

		err := resp.Verify(pub2)
		if err == nil {
			t.Error("expected error for invalid signature")
		}
	})

	t.Run("rejects tampered response", func(t *testing.T) {
		resp, _ := NewAttestationResponse(peerID, version, challenge)
		_ = resp.Sign(priv)

		// Tamper with solution
		resp.Solution = "tampered"

		err := resp.Verify(pub)
		if err == nil {
			t.Error("expected error for tampered response")
		}
	})

	t.Run("rejects unsigned response", func(t *testing.T) {
		resp, _ := NewAttestationResponse(peerID, version, challenge)

		err := resp.Verify(pub)
		if err == nil {
			t.Error("expected error for unsigned response")
		}
	})
}

func TestAttestationResponseVerifyPoW(t *testing.T) {
	peerID := generateTestPeerID(t)
	version := "1.0.0"
	difficulty := 8 // Low difficulty for fast tests
	challenge := "1:8:1706745600:test-resource:MTIzNDU2"

	t.Run("valid PoW verifies successfully", func(t *testing.T) {
		resp, err := NewAttestationResponse(peerID, version, challenge)
		if err != nil {
			t.Fatalf("unexpected error creating response: %v", err)
		}

		if !resp.VerifyPoW(difficulty) {
			t.Error("expected PoW to verify successfully")
		}
	})

	t.Run("higher difficulty fails for lower difficulty solution", func(t *testing.T) {
		resp, err := NewAttestationResponse(peerID, version, challenge)
		if err != nil {
			t.Fatalf("unexpected error creating response: %v", err)
		}

		// Solution was computed for 8 bits, checking 20 bits should fail
		// (statistically very likely to fail)
		if resp.VerifyPoW(20) {
			// This could very rarely pass by chance, so we don't fail hard
			t.Log("warning: solution unexpectedly passed higher difficulty check")
		}
	})

	t.Run("tampered solution fails verification", func(t *testing.T) {
		resp, err := NewAttestationResponse(peerID, version, challenge)
		if err != nil {
			t.Fatalf("unexpected error creating response: %v", err)
		}

		// Tamper with the solution
		resp.Solution = "1:8:1706745600:test-resource:MTIzNDU2:0"

		if resp.VerifyPoW(difficulty) {
			t.Error("tampered solution should not verify")
		}
	})

	t.Run("invalid solution format fails", func(t *testing.T) {
		resp := &AttestationResponse{
			Version:   version,
			PeerID:    peerID,
			Solution:  "invalid",
			Timestamp: time.Now(),
		}

		if resp.VerifyPoW(difficulty) {
			t.Error("invalid solution format should not verify")
		}
	})
}

// ============================================================================
// Integration Tests
// ============================================================================

func TestAttestationRequestResponseFlow(t *testing.T) {
	// Simulate a full attestation flow between two peers
	initiatorPeerID := peer.ID("12D3KooWInitiator123456789")
	responderPeerID := peer.ID("12D3KooWResponder123456789")
	initiatorPub, initiatorPriv := generateTestKeyPair(t)
	responderPub, responderPriv := generateTestKeyPair(t)
	version := "1.0.0"
	difficulty := 8

	// Step 1: Initiator creates and signs a request
	req, err := NewAttestationRequest(initiatorPeerID, version, difficulty)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	if err := req.Sign(initiatorPriv); err != nil {
		t.Fatalf("failed to sign request: %v", err)
	}

	// Step 2: Responder verifies the request signature
	if err := req.Verify(initiatorPub); err != nil {
		t.Fatalf("failed to verify request: %v", err)
	}

	// Step 3: Responder creates and signs a response with solved PoW
	resp, err := NewAttestationResponse(responderPeerID, version, req.Challenge)
	if err != nil {
		t.Fatalf("failed to create response: %v", err)
	}
	if err := resp.Sign(responderPriv); err != nil {
		t.Fatalf("failed to sign response: %v", err)
	}

	// Step 4: Initiator verifies the response signature
	if err := resp.Verify(responderPub); err != nil {
		t.Fatalf("failed to verify response: %v", err)
	}

	// Step 5: Initiator verifies the PoW
	if !resp.VerifyPoW(difficulty) {
		t.Fatal("PoW verification failed")
	}
}

func TestAttestationConcurrentRequests(t *testing.T) {
	peerID := generateTestPeerID(t)
	version := "1.0.0"
	difficulty := 8

	var wg sync.WaitGroup
	numGoroutines := 10
	requests := make([]*AttestationRequest, numGoroutines)
	errors := make([]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req, err := NewAttestationRequest(peerID, version, difficulty)
			requests[idx] = req
			errors[idx] = err
		}(i)
	}

	wg.Wait()

	// All requests should succeed and be unique
	challenges := make(map[string]bool)
	for i, req := range requests {
		if errors[i] != nil {
			t.Errorf("request %d failed: %v", i, errors[i])
			continue
		}
		if req == nil {
			t.Errorf("request %d is nil", i)
			continue
		}
		if challenges[req.Challenge] {
			t.Errorf("request %d has duplicate challenge", i)
		}
		challenges[req.Challenge] = true
	}
}

func TestAttestationConcurrentResponses(t *testing.T) {
	peerID := generateTestPeerID(t)
	version := "1.0.0"
	challenge := "1:8:1706745600:test-resource:MTIzNDU2"

	var wg sync.WaitGroup
	numGoroutines := 10
	responses := make([]*AttestationResponse, numGoroutines)
	errors := make([]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			resp, err := NewAttestationResponse(peerID, version, challenge)
			responses[idx] = resp
			errors[idx] = err
		}(i)
	}

	wg.Wait()

	// All responses should succeed
	for i, resp := range responses {
		if errors[i] != nil {
			t.Errorf("response %d failed: %v", i, errors[i])
			continue
		}
		if resp == nil {
			t.Errorf("response %d is nil", i)
			continue
		}
		// All should have valid PoW (same solution since same challenge)
		if !resp.VerifyPoW(8) {
			t.Errorf("response %d has invalid PoW", i)
		}
	}
}

// ============================================================================
// Serialization Tests (for bytes to sign)
// ============================================================================

func TestAttestationRequestBytesToSign(t *testing.T) {
	peerID := generateTestPeerID(t)
	version := "1.0.0"

	req, _ := NewAttestationRequest(peerID, version, 8)

	// Calling BytesToSign should return consistent bytes
	bytes1 := req.BytesToSign()
	bytes2 := req.BytesToSign()

	if string(bytes1) != string(bytes2) {
		t.Error("BytesToSign should return consistent results")
	}

	if len(bytes1) == 0 {
		t.Error("BytesToSign should return non-empty bytes")
	}
}

func TestAttestationResponseBytesToSign(t *testing.T) {
	peerID := generateTestPeerID(t)
	version := "1.0.0"
	challenge := "1:8:1706745600:test-resource:MTIzNDU2"

	resp, _ := NewAttestationResponse(peerID, version, challenge)

	// Calling BytesToSign should return consistent bytes
	bytes1 := resp.BytesToSign()
	bytes2 := resp.BytesToSign()

	if string(bytes1) != string(bytes2) {
		t.Error("BytesToSign should return consistent results")
	}

	if len(bytes1) == 0 {
		t.Error("BytesToSign should return non-empty bytes")
	}
}

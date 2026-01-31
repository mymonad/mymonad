// Package protocol implements the MyMonad handshake protocol for agent matching.
package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// ============================================================================
// RealIdentity Tests
// ============================================================================

func TestNewRealIdentity(t *testing.T) {
	name := "Alice Smith"
	contact := "alice@example.com"
	pub, _ := generateTestKeyPair(t)

	t.Run("creates valid identity with required fields", func(t *testing.T) {
		identity := NewRealIdentity(name, contact, pub)

		if identity == nil {
			t.Fatal("expected non-nil identity")
		}
		if identity.Name != name {
			t.Errorf("expected name %q, got %q", name, identity.Name)
		}
		if identity.Contact != contact {
			t.Errorf("expected contact %q, got %q", contact, identity.Contact)
		}
		if len(identity.PublicKey) != ed25519.PublicKeySize {
			t.Errorf("expected public key length %d, got %d", ed25519.PublicKeySize, len(identity.PublicKey))
		}
	})

	t.Run("creates identity with empty extra fields", func(t *testing.T) {
		identity := NewRealIdentity(name, contact, pub)

		if identity.Extra == nil {
			t.Error("expected non-nil Extra map")
		}
		if len(identity.Extra) != 0 {
			t.Errorf("expected empty Extra map, got %d entries", len(identity.Extra))
		}
	})
}

func TestRealIdentityAddExtra(t *testing.T) {
	name := "Bob Jones"
	contact := "bob@example.com"
	pub, _ := generateTestKeyPair(t)

	t.Run("adds extra fields successfully", func(t *testing.T) {
		identity := NewRealIdentity(name, contact, pub)
		identity.AddExtra("twitter", "@bob")
		identity.AddExtra("linkedin", "linkedin.com/in/bob")

		if identity.Extra["twitter"] != "@bob" {
			t.Errorf("expected twitter @bob, got %q", identity.Extra["twitter"])
		}
		if identity.Extra["linkedin"] != "linkedin.com/in/bob" {
			t.Errorf("expected linkedin url, got %q", identity.Extra["linkedin"])
		}
	})

	t.Run("overwrites existing extra fields", func(t *testing.T) {
		identity := NewRealIdentity(name, contact, pub)
		identity.AddExtra("key", "value1")
		identity.AddExtra("key", "value2")

		if identity.Extra["key"] != "value2" {
			t.Errorf("expected value2, got %q", identity.Extra["key"])
		}
	})
}

func TestRealIdentityValidate(t *testing.T) {
	pub, _ := generateTestKeyPair(t)

	t.Run("valid identity passes validation", func(t *testing.T) {
		identity := NewRealIdentity("Alice", "alice@example.com", pub)

		err := identity.Validate()
		if err != nil {
			t.Errorf("unexpected validation error: %v", err)
		}
	})

	t.Run("empty name fails validation", func(t *testing.T) {
		identity := NewRealIdentity("", "alice@example.com", pub)

		err := identity.Validate()
		if err == nil {
			t.Error("expected validation error for empty name")
		}
	})

	t.Run("empty contact fails validation", func(t *testing.T) {
		identity := NewRealIdentity("Alice", "", pub)

		err := identity.Validate()
		if err == nil {
			t.Error("expected validation error for empty contact")
		}
	})

	t.Run("nil public key fails validation", func(t *testing.T) {
		identity := &RealIdentity{
			Name:      "Alice",
			Contact:   "alice@example.com",
			PublicKey: nil,
			Extra:     make(map[string]string),
		}

		err := identity.Validate()
		if err == nil {
			t.Error("expected validation error for nil public key")
		}
	})

	t.Run("invalid public key length fails validation", func(t *testing.T) {
		identity := &RealIdentity{
			Name:      "Alice",
			Contact:   "alice@example.com",
			PublicKey: []byte("short"),
			Extra:     make(map[string]string),
		}

		err := identity.Validate()
		if err == nil {
			t.Error("expected validation error for invalid public key length")
		}
	})
}

// ============================================================================
// UnmaskRequest Tests
// ============================================================================

func TestNewUnmaskRequest(t *testing.T) {
	peerID := generateTestPeerID(t)

	t.Run("creates approved request", func(t *testing.T) {
		req := NewUnmaskRequest(peerID, true)

		if req == nil {
			t.Fatal("expected non-nil request")
		}
		if req.PeerID != peerID {
			t.Errorf("expected peerID %v, got %v", peerID, req.PeerID)
		}
		if !req.Approved {
			t.Error("expected Approved to be true")
		}
		if req.Timestamp.IsZero() {
			t.Error("expected non-zero timestamp")
		}
		if req.Signature != nil {
			t.Error("expected nil signature before Sign()")
		}
	})

	t.Run("creates rejected request", func(t *testing.T) {
		req := NewUnmaskRequest(peerID, false)

		if req.Approved {
			t.Error("expected Approved to be false")
		}
	})

	t.Run("timestamp is recent", func(t *testing.T) {
		req := NewUnmaskRequest(peerID, true)

		if time.Since(req.Timestamp) > time.Second {
			t.Errorf("timestamp should be recent, got %v", req.Timestamp)
		}
	})
}

func TestUnmaskRequestSign(t *testing.T) {
	peerID := generateTestPeerID(t)
	_, priv := generateTestKeyPair(t)

	t.Run("signs request successfully", func(t *testing.T) {
		req := NewUnmaskRequest(peerID, true)

		err := req.Sign(priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(req.Signature) != ed25519.SignatureSize {
			t.Errorf("expected signature length %d, got %d", ed25519.SignatureSize, len(req.Signature))
		}
	})

	t.Run("signature is deterministic for same content", func(t *testing.T) {
		req := NewUnmaskRequest(peerID, true)

		err := req.Sign(priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sig1 := make([]byte, len(req.Signature))
		copy(sig1, req.Signature)

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

func TestUnmaskRequestVerify(t *testing.T) {
	peerID := generateTestPeerID(t)
	pub, priv := generateTestKeyPair(t)
	pub2, _ := generateTestKeyPair(t)

	t.Run("verifies valid signature", func(t *testing.T) {
		req := NewUnmaskRequest(peerID, true)
		_ = req.Sign(priv)

		err := req.Verify(pub)
		if err != nil {
			t.Fatalf("expected valid signature, got error: %v", err)
		}
	})

	t.Run("rejects invalid signature", func(t *testing.T) {
		req := NewUnmaskRequest(peerID, true)
		_ = req.Sign(priv)

		err := req.Verify(pub2)
		if err == nil {
			t.Error("expected error for invalid signature")
		}
	})

	t.Run("rejects tampered request", func(t *testing.T) {
		req := NewUnmaskRequest(peerID, true)
		_ = req.Sign(priv)

		req.Approved = false

		err := req.Verify(pub)
		if err == nil {
			t.Error("expected error for tampered request")
		}
	})

	t.Run("rejects unsigned request", func(t *testing.T) {
		req := NewUnmaskRequest(peerID, true)

		err := req.Verify(pub)
		if err == nil {
			t.Error("expected error for unsigned request")
		}
	})
}

func TestUnmaskRequestBytesToSign(t *testing.T) {
	peerID := generateTestPeerID(t)

	t.Run("returns consistent bytes", func(t *testing.T) {
		req := NewUnmaskRequest(peerID, true)

		bytes1 := req.BytesToSign()
		bytes2 := req.BytesToSign()

		if string(bytes1) != string(bytes2) {
			t.Error("BytesToSign should return consistent results")
		}

		if len(bytes1) == 0 {
			t.Error("BytesToSign should return non-empty bytes")
		}
	})

	t.Run("different approval produces different bytes", func(t *testing.T) {
		req1 := NewUnmaskRequest(peerID, true)
		req2 := NewUnmaskRequest(peerID, false)
		// Set same timestamp for comparison
		req2.Timestamp = req1.Timestamp

		bytes1 := req1.BytesToSign()
		bytes2 := req2.BytesToSign()

		if string(bytes1) == string(bytes2) {
			t.Error("different approval should produce different bytes")
		}
	})
}

// ============================================================================
// UnmaskResponse Tests
// ============================================================================

func TestNewUnmaskResponse(t *testing.T) {
	peerID := generateTestPeerID(t)
	pub, _ := generateTestKeyPair(t)
	identity := NewRealIdentity("Alice", "alice@example.com", pub)

	t.Run("creates approved response with identity", func(t *testing.T) {
		resp := NewUnmaskResponse(peerID, true, identity)

		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if resp.PeerID != peerID {
			t.Errorf("expected peerID %v, got %v", peerID, resp.PeerID)
		}
		if !resp.Approved {
			t.Error("expected Approved to be true")
		}
		if resp.Identity == nil {
			t.Error("expected non-nil identity for approved response")
		}
		if resp.Identity.Name != identity.Name {
			t.Errorf("expected name %q, got %q", identity.Name, resp.Identity.Name)
		}
		if resp.Timestamp.IsZero() {
			t.Error("expected non-zero timestamp")
		}
		if resp.Signature != nil {
			t.Error("expected nil signature before Sign()")
		}
	})

	t.Run("creates rejected response without identity", func(t *testing.T) {
		resp := NewUnmaskResponse(peerID, false, nil)

		if resp.Approved {
			t.Error("expected Approved to be false")
		}
		if resp.Identity != nil {
			t.Error("expected nil identity for rejected response")
		}
	})

	t.Run("does not include identity when rejected even if provided", func(t *testing.T) {
		resp := NewUnmaskResponse(peerID, false, identity)

		if resp.Identity != nil {
			t.Error("identity should not be included when not approved")
		}
	})

	t.Run("timestamp is recent", func(t *testing.T) {
		resp := NewUnmaskResponse(peerID, true, identity)

		if time.Since(resp.Timestamp) > time.Second {
			t.Errorf("timestamp should be recent, got %v", resp.Timestamp)
		}
	})
}

func TestUnmaskResponseSign(t *testing.T) {
	peerID := generateTestPeerID(t)
	pub, priv := generateTestKeyPair(t)
	identity := NewRealIdentity("Alice", "alice@example.com", pub)

	t.Run("signs response successfully", func(t *testing.T) {
		resp := NewUnmaskResponse(peerID, true, identity)

		err := resp.Sign(priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(resp.Signature) != ed25519.SignatureSize {
			t.Errorf("expected signature length %d, got %d", ed25519.SignatureSize, len(resp.Signature))
		}
	})

	t.Run("signs rejected response successfully", func(t *testing.T) {
		resp := NewUnmaskResponse(peerID, false, nil)

		err := resp.Sign(priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(resp.Signature) != ed25519.SignatureSize {
			t.Errorf("expected signature length %d, got %d", ed25519.SignatureSize, len(resp.Signature))
		}
	})
}

func TestUnmaskResponseVerify(t *testing.T) {
	peerID := generateTestPeerID(t)
	pub, priv := generateTestKeyPair(t)
	pub2, _ := generateTestKeyPair(t)
	identity := NewRealIdentity("Alice", "alice@example.com", pub)

	t.Run("verifies valid signature", func(t *testing.T) {
		resp := NewUnmaskResponse(peerID, true, identity)
		_ = resp.Sign(priv)

		err := resp.Verify(pub)
		if err != nil {
			t.Fatalf("expected valid signature, got error: %v", err)
		}
	})

	t.Run("rejects invalid signature", func(t *testing.T) {
		resp := NewUnmaskResponse(peerID, true, identity)
		_ = resp.Sign(priv)

		err := resp.Verify(pub2)
		if err == nil {
			t.Error("expected error for invalid signature")
		}
	})

	t.Run("rejects tampered response", func(t *testing.T) {
		resp := NewUnmaskResponse(peerID, true, identity)
		_ = resp.Sign(priv)

		resp.Approved = false

		err := resp.Verify(pub)
		if err == nil {
			t.Error("expected error for tampered response")
		}
	})

	t.Run("rejects unsigned response", func(t *testing.T) {
		resp := NewUnmaskResponse(peerID, true, identity)

		err := resp.Verify(pub)
		if err == nil {
			t.Error("expected error for unsigned response")
		}
	})
}

func TestUnmaskResponseBytesToSign(t *testing.T) {
	peerID := generateTestPeerID(t)
	pub, _ := generateTestKeyPair(t)
	identity := NewRealIdentity("Alice", "alice@example.com", pub)

	t.Run("returns consistent bytes", func(t *testing.T) {
		resp := NewUnmaskResponse(peerID, true, identity)

		bytes1 := resp.BytesToSign()
		bytes2 := resp.BytesToSign()

		if string(bytes1) != string(bytes2) {
			t.Error("BytesToSign should return consistent results")
		}

		if len(bytes1) == 0 {
			t.Error("BytesToSign should return non-empty bytes")
		}
	})

	t.Run("different approval produces different bytes", func(t *testing.T) {
		resp1 := NewUnmaskResponse(peerID, true, identity)
		resp2 := NewUnmaskResponse(peerID, false, nil)
		resp2.Timestamp = resp1.Timestamp

		bytes1 := resp1.BytesToSign()
		bytes2 := resp2.BytesToSign()

		if string(bytes1) == string(bytes2) {
			t.Error("different approval should produce different bytes")
		}
	})

	t.Run("includes identity in bytes when approved", func(t *testing.T) {
		resp1 := NewUnmaskResponse(peerID, true, identity)
		identity2 := NewRealIdentity("Bob", "bob@example.com", pub)
		resp2 := NewUnmaskResponse(peerID, true, identity2)
		resp2.Timestamp = resp1.Timestamp

		bytes1 := resp1.BytesToSign()
		bytes2 := resp2.BytesToSign()

		if string(bytes1) == string(bytes2) {
			t.Error("different identity should produce different bytes")
		}
	})
}

// ============================================================================
// CheckMutualApproval Tests
// ============================================================================

func TestCheckMutualApproval(t *testing.T) {
	peerID1 := peer.ID("12D3KooWInitiator123456789")
	peerID2 := peer.ID("12D3KooWResponder123456789")

	t.Run("both approved returns true", func(t *testing.T) {
		req := NewUnmaskRequest(peerID1, true)
		resp := NewUnmaskResponse(peerID2, true, nil)

		result := CheckMutualApproval(req, resp)
		if !result {
			t.Error("expected mutual approval when both approve")
		}
	})

	t.Run("request rejected returns false", func(t *testing.T) {
		req := NewUnmaskRequest(peerID1, false)
		resp := NewUnmaskResponse(peerID2, true, nil)

		result := CheckMutualApproval(req, resp)
		if result {
			t.Error("expected no mutual approval when request is rejected")
		}
	})

	t.Run("response rejected returns false", func(t *testing.T) {
		req := NewUnmaskRequest(peerID1, true)
		resp := NewUnmaskResponse(peerID2, false, nil)

		result := CheckMutualApproval(req, resp)
		if result {
			t.Error("expected no mutual approval when response is rejected")
		}
	})

	t.Run("both rejected returns false", func(t *testing.T) {
		req := NewUnmaskRequest(peerID1, false)
		resp := NewUnmaskResponse(peerID2, false, nil)

		result := CheckMutualApproval(req, resp)
		if result {
			t.Error("expected no mutual approval when both reject")
		}
	})

	t.Run("nil request returns false", func(t *testing.T) {
		resp := NewUnmaskResponse(peerID2, true, nil)

		result := CheckMutualApproval(nil, resp)
		if result {
			t.Error("expected no mutual approval with nil request")
		}
	})

	t.Run("nil response returns false", func(t *testing.T) {
		req := NewUnmaskRequest(peerID1, true)

		result := CheckMutualApproval(req, nil)
		if result {
			t.Error("expected no mutual approval with nil response")
		}
	})

	t.Run("both nil returns false", func(t *testing.T) {
		result := CheckMutualApproval(nil, nil)
		if result {
			t.Error("expected no mutual approval with nil inputs")
		}
	})
}

// ============================================================================
// Integration Tests
// ============================================================================

func TestUnmaskRequestResponseFlow(t *testing.T) {
	initiatorPeerID := peer.ID("12D3KooWInitiator123456789")
	responderPeerID := peer.ID("12D3KooWResponder123456789")
	initiatorPub, initiatorPriv := generateTestKeyPair(t)
	responderPub, responderPriv := generateTestKeyPair(t)

	// Create identity for responder
	responderIdentity := NewRealIdentity("Bob Jones", "bob@example.com", responderPub)
	responderIdentity.AddExtra("phone", "+1-555-0123")

	t.Run("successful mutual unmask flow", func(t *testing.T) {
		// Step 1: Initiator creates and signs an unmask request (approving)
		req := NewUnmaskRequest(initiatorPeerID, true)
		if err := req.Sign(initiatorPriv); err != nil {
			t.Fatalf("failed to sign request: %v", err)
		}

		// Step 2: Responder verifies the request signature
		if err := req.Verify(initiatorPub); err != nil {
			t.Fatalf("failed to verify request: %v", err)
		}

		// Step 3: Responder creates and signs a response with identity (also approving)
		resp := NewUnmaskResponse(responderPeerID, true, responderIdentity)
		if err := resp.Sign(responderPriv); err != nil {
			t.Fatalf("failed to sign response: %v", err)
		}

		// Step 4: Initiator verifies the response signature
		if err := resp.Verify(responderPub); err != nil {
			t.Fatalf("failed to verify response: %v", err)
		}

		// Step 5: Check mutual approval
		if !CheckMutualApproval(req, resp) {
			t.Fatal("expected mutual approval")
		}

		// Step 6: Verify identity was exchanged
		if resp.Identity == nil {
			t.Fatal("expected identity in response")
		}
		if resp.Identity.Name != "Bob Jones" {
			t.Errorf("expected name Bob Jones, got %q", resp.Identity.Name)
		}
		if resp.Identity.Extra["phone"] != "+1-555-0123" {
			t.Errorf("expected phone +1-555-0123, got %q", resp.Identity.Extra["phone"])
		}
	})

	t.Run("failed unmask flow - initiator rejects", func(t *testing.T) {
		req := NewUnmaskRequest(initiatorPeerID, false)
		_ = req.Sign(initiatorPriv)

		resp := NewUnmaskResponse(responderPeerID, true, responderIdentity)
		_ = resp.Sign(responderPriv)

		if CheckMutualApproval(req, resp) {
			t.Error("expected no mutual approval when initiator rejects")
		}
	})

	t.Run("failed unmask flow - responder rejects", func(t *testing.T) {
		req := NewUnmaskRequest(initiatorPeerID, true)
		_ = req.Sign(initiatorPriv)

		resp := NewUnmaskResponse(responderPeerID, false, nil)
		_ = resp.Sign(responderPriv)

		if CheckMutualApproval(req, resp) {
			t.Error("expected no mutual approval when responder rejects")
		}

		// Identity should not be present
		if resp.Identity != nil {
			t.Error("identity should not be present when rejected")
		}
	})
}

func TestUnmaskConcurrentRequests(t *testing.T) {
	peerID := generateTestPeerID(t)

	var wg sync.WaitGroup
	numGoroutines := 10
	requests := make([]*UnmaskRequest, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			requests[idx] = NewUnmaskRequest(peerID, idx%2 == 0)
		}(i)
	}

	wg.Wait()

	for i, req := range requests {
		if req == nil {
			t.Errorf("request %d is nil", i)
			continue
		}
		expectedApproval := i%2 == 0
		if req.Approved != expectedApproval {
			t.Errorf("request %d: expected Approved=%v, got %v", i, expectedApproval, req.Approved)
		}
	}
}

func TestUnmaskConcurrentResponses(t *testing.T) {
	peerID := generateTestPeerID(t)
	pub, _ := generateTestKeyPair(t)
	identity := NewRealIdentity("Alice", "alice@example.com", pub)

	var wg sync.WaitGroup
	numGoroutines := 10
	responses := make([]*UnmaskResponse, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			approved := idx%2 == 0
			var id *RealIdentity
			if approved {
				id = identity
			}
			responses[idx] = NewUnmaskResponse(peerID, approved, id)
		}(i)
	}

	wg.Wait()

	for i, resp := range responses {
		if resp == nil {
			t.Errorf("response %d is nil", i)
			continue
		}
		expectedApproval := i%2 == 0
		if resp.Approved != expectedApproval {
			t.Errorf("response %d: expected Approved=%v, got %v", i, expectedApproval, resp.Approved)
		}
		if expectedApproval && resp.Identity == nil {
			t.Errorf("response %d: expected identity for approved response", i)
		}
		if !expectedApproval && resp.Identity != nil {
			t.Errorf("response %d: unexpected identity for rejected response", i)
		}
	}
}

func TestUnmaskConcurrentSignAndVerify(t *testing.T) {
	peerID := generateTestPeerID(t)
	pub, priv := generateTestKeyPair(t)
	identity := NewRealIdentity("Alice", "alice@example.com", pub)

	var wg sync.WaitGroup
	numGoroutines := 10
	errs := make([]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Create, sign, and verify request
			req := NewUnmaskRequest(peerID, true)
			if err := req.Sign(priv); err != nil {
				errs[idx] = err
				return
			}
			if err := req.Verify(pub); err != nil {
				errs[idx] = err
				return
			}
			// Create, sign, and verify response
			resp := NewUnmaskResponse(peerID, true, identity)
			if err := resp.Sign(priv); err != nil {
				errs[idx] = err
				return
			}
			if err := resp.Verify(pub); err != nil {
				errs[idx] = err
				return
			}
		}(i)
	}

	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d failed: %v", i, err)
		}
	}
}

// ============================================================================
// Edge Case Tests
// ============================================================================

func TestRealIdentityClone(t *testing.T) {
	pub, _ := generateTestKeyPair(t)
	original := NewRealIdentity("Alice", "alice@example.com", pub)
	original.AddExtra("twitter", "@alice")

	t.Run("clones identity correctly", func(t *testing.T) {
		clone := original.Clone()

		if clone == original {
			t.Error("clone should be a different instance")
		}
		if clone.Name != original.Name {
			t.Errorf("expected name %q, got %q", original.Name, clone.Name)
		}
		if clone.Contact != original.Contact {
			t.Errorf("expected contact %q, got %q", original.Contact, clone.Contact)
		}
		if string(clone.PublicKey) != string(original.PublicKey) {
			t.Error("public key should match")
		}
		if clone.Extra["twitter"] != original.Extra["twitter"] {
			t.Error("extra fields should match")
		}
	})

	t.Run("clone is independent", func(t *testing.T) {
		clone := original.Clone()

		// Modify clone
		clone.Name = "Modified"
		clone.Extra["twitter"] = "@modified"

		// Original should be unchanged
		if original.Name == "Modified" {
			t.Error("original name should not be modified")
		}
		if original.Extra["twitter"] == "@modified" {
			t.Error("original extra should not be modified")
		}
	})
}

// ============================================================================
// Error Tests
// ============================================================================

func TestUnmaskErrors(t *testing.T) {
	t.Run("ErrUnmaskEmptyName is defined", func(t *testing.T) {
		if ErrUnmaskEmptyName == nil {
			t.Error("ErrUnmaskEmptyName should be defined")
		}
	})

	t.Run("ErrUnmaskEmptyContact is defined", func(t *testing.T) {
		if ErrUnmaskEmptyContact == nil {
			t.Error("ErrUnmaskEmptyContact should be defined")
		}
	})

	t.Run("ErrUnmaskInvalidPublicKey is defined", func(t *testing.T) {
		if ErrUnmaskInvalidPublicKey == nil {
			t.Error("ErrUnmaskInvalidPublicKey should be defined")
		}
	})
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkNewUnmaskRequest(b *testing.B) {
	peerID := peer.ID("12D3KooWTestPeerID123456789")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewUnmaskRequest(peerID, true)
	}
}

func BenchmarkUnmaskRequestSign(b *testing.B) {
	peerID := peer.ID("12D3KooWTestPeerID123456789")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	req := NewUnmaskRequest(peerID, true)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.Signature = nil
		_ = req.Sign(priv)
	}
}

func BenchmarkUnmaskRequestVerify(b *testing.B) {
	peerID := peer.ID("12D3KooWTestPeerID123456789")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	req := NewUnmaskRequest(peerID, true)
	_ = req.Sign(priv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = req.Verify(pub)
	}
}

func BenchmarkCheckMutualApproval(b *testing.B) {
	peerID1 := peer.ID("12D3KooWInitiator123456789")
	peerID2 := peer.ID("12D3KooWResponder123456789")
	req := NewUnmaskRequest(peerID1, true)
	resp := NewUnmaskResponse(peerID2, true, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckMutualApproval(req, resp)
	}
}

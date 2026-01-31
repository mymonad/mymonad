// Package protocol implements the MyMonad handshake protocol for agent matching.
package protocol

import (
	"crypto/ed25519"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// ============================================================================
// DealBreaker Struct Tests
// ============================================================================

func TestDealBreaker(t *testing.T) {
	t.Run("creates deal-breaker with question and answer", func(t *testing.T) {
		db := DealBreaker{
			Question: "Do you want children?",
			Answer:   true,
		}

		if db.Question != "Do you want children?" {
			t.Errorf("expected question 'Do you want children?', got %q", db.Question)
		}
		if db.Answer != true {
			t.Error("expected answer true")
		}
	})

	t.Run("creates deal-breaker with false answer", func(t *testing.T) {
		db := DealBreaker{
			Question: "Are you a smoker?",
			Answer:   false,
		}

		if db.Question != "Are you a smoker?" {
			t.Errorf("expected question 'Are you a smoker?', got %q", db.Question)
		}
		if db.Answer != false {
			t.Error("expected answer false")
		}
	})
}

// ============================================================================
// DealBreakerRequest Tests
// ============================================================================

func TestNewDealBreakerRequest(t *testing.T) {
	peerID := generateTestPeerID(t)
	questions := [3]DealBreaker{
		{Question: "Do you want children?", Answer: true},
		{Question: "Are you a smoker?", Answer: false},
		{Question: "Do you live in Europe?", Answer: true},
	}

	t.Run("creates valid request with questions", func(t *testing.T) {
		req := NewDealBreakerRequest(peerID, questions)

		if req == nil {
			t.Fatal("expected non-nil request")
		}
		if req.PeerID != peerID {
			t.Errorf("expected peerID %v, got %v", peerID, req.PeerID)
		}
		if req.Questions != questions {
			t.Error("expected questions to match")
		}
		if req.Timestamp.IsZero() {
			t.Error("expected non-zero timestamp")
		}
		if req.Signature != nil {
			t.Error("expected nil signature before Sign()")
		}
	})

	t.Run("timestamp is recent", func(t *testing.T) {
		req := NewDealBreakerRequest(peerID, questions)

		if time.Since(req.Timestamp) > time.Second {
			t.Errorf("timestamp should be recent, got %v", req.Timestamp)
		}
	})

	t.Run("stores exactly 3 questions", func(t *testing.T) {
		req := NewDealBreakerRequest(peerID, questions)

		if len(req.Questions) != 3 {
			t.Errorf("expected exactly 3 questions, got %d", len(req.Questions))
		}
	})
}

func TestDealBreakerRequestSign(t *testing.T) {
	peerID := generateTestPeerID(t)
	_, priv := generateTestKeyPair(t)
	questions := [3]DealBreaker{
		{Question: "Do you want children?", Answer: true},
		{Question: "Are you a smoker?", Answer: false},
		{Question: "Do you live in Europe?", Answer: true},
	}

	t.Run("signs request successfully", func(t *testing.T) {
		req := NewDealBreakerRequest(peerID, questions)

		err := req.Sign(priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(req.Signature) != ed25519.SignatureSize {
			t.Errorf("expected signature length %d, got %d", ed25519.SignatureSize, len(req.Signature))
		}
	})

	t.Run("signature is deterministic for same content", func(t *testing.T) {
		req := NewDealBreakerRequest(peerID, questions)

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

func TestDealBreakerRequestVerify(t *testing.T) {
	peerID := generateTestPeerID(t)
	pub, priv := generateTestKeyPair(t)
	pub2, _ := generateTestKeyPair(t) // Different key pair
	questions := [3]DealBreaker{
		{Question: "Do you want children?", Answer: true},
		{Question: "Are you a smoker?", Answer: false},
		{Question: "Do you live in Europe?", Answer: true},
	}

	t.Run("verifies valid signature", func(t *testing.T) {
		req := NewDealBreakerRequest(peerID, questions)
		_ = req.Sign(priv)

		err := req.Verify(pub)
		if err != nil {
			t.Fatalf("expected valid signature, got error: %v", err)
		}
	})

	t.Run("rejects invalid signature", func(t *testing.T) {
		req := NewDealBreakerRequest(peerID, questions)
		_ = req.Sign(priv)

		// Verify with different key
		err := req.Verify(pub2)
		if err == nil {
			t.Error("expected error for invalid signature")
		}
	})

	t.Run("rejects tampered request", func(t *testing.T) {
		req := NewDealBreakerRequest(peerID, questions)
		_ = req.Sign(priv)

		// Tamper with question
		req.Questions[0].Answer = false

		err := req.Verify(pub)
		if err == nil {
			t.Error("expected error for tampered request")
		}
	})

	t.Run("rejects unsigned request", func(t *testing.T) {
		req := NewDealBreakerRequest(peerID, questions)

		err := req.Verify(pub)
		if err == nil {
			t.Error("expected error for unsigned request")
		}
	})
}

// ============================================================================
// DealBreakerResponse Tests
// ============================================================================

func TestNewDealBreakerResponse(t *testing.T) {
	peerID := generateTestPeerID(t)

	// My questions (what I want from the peer)
	myQuestions := [3]DealBreaker{
		{Question: "Do you want children?", Answer: true},
		{Question: "Are you a smoker?", Answer: false},
		{Question: "Do you live in Europe?", Answer: true},
	}

	// Peer's questions (I need to answer these)
	peerQuestions := [3]DealBreaker{
		{Question: "Are you religious?", Answer: true},
		{Question: "Do you have pets?", Answer: true},
		{Question: "Are you a morning person?", Answer: false},
	}

	t.Run("creates valid response with answers", func(t *testing.T) {
		// My answers to peer's questions
		myAnswers := [3]bool{true, true, false} // Matches all peer's expected answers
		resp := NewDealBreakerResponse(peerID, myAnswers, peerQuestions)

		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if resp.PeerID != peerID {
			t.Errorf("expected peerID %v, got %v", peerID, resp.PeerID)
		}
		if resp.Answers != myAnswers {
			t.Error("expected answers to match")
		}
		if resp.Timestamp.IsZero() {
			t.Error("expected non-zero timestamp")
		}
		if resp.Signature != nil {
			t.Error("expected nil signature before Sign()")
		}
	})

	t.Run("matched is true when all answers match expectations", func(t *testing.T) {
		// Answers match peer's expected answers
		myAnswers := [3]bool{true, true, false}
		resp := NewDealBreakerResponse(peerID, myAnswers, peerQuestions)

		if !resp.Matched {
			t.Error("expected Matched to be true when all answers match")
		}
	})

	t.Run("matched is false when one answer differs", func(t *testing.T) {
		// First answer differs from peer's expectation
		myAnswers := [3]bool{false, true, false}
		resp := NewDealBreakerResponse(peerID, myAnswers, peerQuestions)

		if resp.Matched {
			t.Error("expected Matched to be false when any answer differs")
		}
	})

	t.Run("matched is false when all answers differ", func(t *testing.T) {
		// All answers differ from peer's expectations
		myAnswers := [3]bool{false, false, true}
		resp := NewDealBreakerResponse(peerID, myAnswers, peerQuestions)

		if resp.Matched {
			t.Error("expected Matched to be false when all answers differ")
		}
	})

	t.Run("timestamp is recent", func(t *testing.T) {
		myAnswers := [3]bool{true, true, false}
		resp := NewDealBreakerResponse(peerID, myAnswers, myQuestions)

		if time.Since(resp.Timestamp) > time.Second {
			t.Errorf("timestamp should be recent, got %v", resp.Timestamp)
		}
	})
}

func TestDealBreakerResponseSign(t *testing.T) {
	peerID := generateTestPeerID(t)
	_, priv := generateTestKeyPair(t)
	peerQuestions := [3]DealBreaker{
		{Question: "Are you religious?", Answer: true},
		{Question: "Do you have pets?", Answer: true},
		{Question: "Are you a morning person?", Answer: false},
	}
	myAnswers := [3]bool{true, true, false}

	t.Run("signs response successfully", func(t *testing.T) {
		resp := NewDealBreakerResponse(peerID, myAnswers, peerQuestions)

		err := resp.Sign(priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(resp.Signature) != ed25519.SignatureSize {
			t.Errorf("expected signature length %d, got %d", ed25519.SignatureSize, len(resp.Signature))
		}
	})
}

func TestDealBreakerResponseVerify(t *testing.T) {
	peerID := generateTestPeerID(t)
	pub, priv := generateTestKeyPair(t)
	pub2, _ := generateTestKeyPair(t)
	peerQuestions := [3]DealBreaker{
		{Question: "Are you religious?", Answer: true},
		{Question: "Do you have pets?", Answer: true},
		{Question: "Are you a morning person?", Answer: false},
	}
	myAnswers := [3]bool{true, true, false}

	t.Run("verifies valid signature", func(t *testing.T) {
		resp := NewDealBreakerResponse(peerID, myAnswers, peerQuestions)
		_ = resp.Sign(priv)

		err := resp.Verify(pub)
		if err != nil {
			t.Fatalf("expected valid signature, got error: %v", err)
		}
	})

	t.Run("rejects invalid signature", func(t *testing.T) {
		resp := NewDealBreakerResponse(peerID, myAnswers, peerQuestions)
		_ = resp.Sign(priv)

		err := resp.Verify(pub2)
		if err == nil {
			t.Error("expected error for invalid signature")
		}
	})

	t.Run("rejects tampered response", func(t *testing.T) {
		resp := NewDealBreakerResponse(peerID, myAnswers, peerQuestions)
		_ = resp.Sign(priv)

		// Tamper with answer
		resp.Answers[0] = !resp.Answers[0]

		err := resp.Verify(pub)
		if err == nil {
			t.Error("expected error for tampered response")
		}
	})

	t.Run("rejects unsigned response", func(t *testing.T) {
		resp := NewDealBreakerResponse(peerID, myAnswers, peerQuestions)

		err := resp.Verify(pub)
		if err == nil {
			t.Error("expected error for unsigned response")
		}
	})
}

// ============================================================================
// CheckMatch Tests
// ============================================================================

func TestCheckMatch(t *testing.T) {
	t.Run("returns true when all answers match expectations", func(t *testing.T) {
		myQuestions := [3]DealBreaker{
			{Question: "Do you want children?", Answer: true},
			{Question: "Are you a smoker?", Answer: false},
			{Question: "Do you live in Europe?", Answer: true},
		}
		peerAnswers := [3]bool{true, false, true}

		if !CheckMatch(myQuestions, peerAnswers) {
			t.Error("expected match when all answers match expectations")
		}
	})

	t.Run("returns false when first answer differs", func(t *testing.T) {
		myQuestions := [3]DealBreaker{
			{Question: "Do you want children?", Answer: true},
			{Question: "Are you a smoker?", Answer: false},
			{Question: "Do you live in Europe?", Answer: true},
		}
		peerAnswers := [3]bool{false, false, true} // First differs

		if CheckMatch(myQuestions, peerAnswers) {
			t.Error("expected no match when first answer differs")
		}
	})

	t.Run("returns false when second answer differs", func(t *testing.T) {
		myQuestions := [3]DealBreaker{
			{Question: "Do you want children?", Answer: true},
			{Question: "Are you a smoker?", Answer: false},
			{Question: "Do you live in Europe?", Answer: true},
		}
		peerAnswers := [3]bool{true, true, true} // Second differs

		if CheckMatch(myQuestions, peerAnswers) {
			t.Error("expected no match when second answer differs")
		}
	})

	t.Run("returns false when third answer differs", func(t *testing.T) {
		myQuestions := [3]DealBreaker{
			{Question: "Do you want children?", Answer: true},
			{Question: "Are you a smoker?", Answer: false},
			{Question: "Do you live in Europe?", Answer: true},
		}
		peerAnswers := [3]bool{true, false, false} // Third differs

		if CheckMatch(myQuestions, peerAnswers) {
			t.Error("expected no match when third answer differs")
		}
	})

	t.Run("returns false when all answers differ", func(t *testing.T) {
		myQuestions := [3]DealBreaker{
			{Question: "Do you want children?", Answer: true},
			{Question: "Are you a smoker?", Answer: false},
			{Question: "Do you live in Europe?", Answer: true},
		}
		peerAnswers := [3]bool{false, true, false} // All differ

		if CheckMatch(myQuestions, peerAnswers) {
			t.Error("expected no match when all answers differ")
		}
	})

	t.Run("handles all-false expectations", func(t *testing.T) {
		myQuestions := [3]DealBreaker{
			{Question: "Are you a smoker?", Answer: false},
			{Question: "Do you drink?", Answer: false},
			{Question: "Do you do drugs?", Answer: false},
		}
		peerAnswers := [3]bool{false, false, false}

		if !CheckMatch(myQuestions, peerAnswers) {
			t.Error("expected match for all-false expectations with all-false answers")
		}
	})

	t.Run("handles all-true expectations", func(t *testing.T) {
		myQuestions := [3]DealBreaker{
			{Question: "Do you want children?", Answer: true},
			{Question: "Do you like travel?", Answer: true},
			{Question: "Are you employed?", Answer: true},
		}
		peerAnswers := [3]bool{true, true, true}

		if !CheckMatch(myQuestions, peerAnswers) {
			t.Error("expected match for all-true expectations with all-true answers")
		}
	})
}

// ============================================================================
// Integration Tests
// ============================================================================

func TestDealBreakerRequestResponseFlow(t *testing.T) {
	// Simulate a full deal-breaker flow between two peers
	initiatorPeerID := peer.ID("12D3KooWInitiator123456789")
	responderPeerID := peer.ID("12D3KooWResponder123456789")
	initiatorPub, initiatorPriv := generateTestKeyPair(t)
	responderPub, responderPriv := generateTestKeyPair(t)

	// Initiator's questions (what they want from responder)
	initiatorQuestions := [3]DealBreaker{
		{Question: "Do you want children?", Answer: true},
		{Question: "Are you a smoker?", Answer: false},
		{Question: "Do you live in Europe?", Answer: true},
	}

	// Responder's questions (what they want from initiator)
	responderQuestions := [3]DealBreaker{
		{Question: "Are you religious?", Answer: false},
		{Question: "Do you have pets?", Answer: true},
		{Question: "Are you a morning person?", Answer: false},
	}

	// Step 1: Initiator creates and signs their request
	initiatorReq := NewDealBreakerRequest(initiatorPeerID, initiatorQuestions)
	if err := initiatorReq.Sign(initiatorPriv); err != nil {
		t.Fatalf("failed to sign initiator request: %v", err)
	}

	// Step 2: Responder creates and signs their request
	responderReq := NewDealBreakerRequest(responderPeerID, responderQuestions)
	if err := responderReq.Sign(responderPriv); err != nil {
		t.Fatalf("failed to sign responder request: %v", err)
	}

	// Step 3: Initiator verifies responder's request
	if err := responderReq.Verify(responderPub); err != nil {
		t.Fatalf("failed to verify responder request: %v", err)
	}

	// Step 4: Responder verifies initiator's request
	if err := initiatorReq.Verify(initiatorPub); err != nil {
		t.Fatalf("failed to verify initiator request: %v", err)
	}

	// Step 5: Initiator answers responder's questions
	// (Initiator: not religious, has pets, not a morning person - matches responder's expectations)
	initiatorAnswers := [3]bool{false, true, false}
	initiatorResp := NewDealBreakerResponse(initiatorPeerID, initiatorAnswers, responderQuestions)
	if err := initiatorResp.Sign(initiatorPriv); err != nil {
		t.Fatalf("failed to sign initiator response: %v", err)
	}

	// Step 6: Responder answers initiator's questions
	// (Responder: wants children, not a smoker, lives in Europe - matches initiator's expectations)
	responderAnswers := [3]bool{true, false, true}
	responderResp := NewDealBreakerResponse(responderPeerID, responderAnswers, initiatorQuestions)
	if err := responderResp.Sign(responderPriv); err != nil {
		t.Fatalf("failed to sign responder response: %v", err)
	}

	// Step 7: Verify responses
	if err := initiatorResp.Verify(initiatorPub); err != nil {
		t.Fatalf("failed to verify initiator response: %v", err)
	}
	if err := responderResp.Verify(responderPub); err != nil {
		t.Fatalf("failed to verify responder response: %v", err)
	}

	// Step 8: Check matches
	if !CheckMatch(initiatorQuestions, responderResp.Answers) {
		t.Error("expected initiator's questions to match responder's answers")
	}
	if !CheckMatch(responderQuestions, initiatorResp.Answers) {
		t.Error("expected responder's questions to match initiator's answers")
	}

	// Verify the Matched field was computed correctly
	if !initiatorResp.Matched {
		t.Error("expected initiator response Matched to be true")
	}
	if !responderResp.Matched {
		t.Error("expected responder response Matched to be true")
	}
}

func TestDealBreakerMismatchFlow(t *testing.T) {
	// Simulate a deal-breaker exchange where there's a mismatch
	responderPeerID := peer.ID("12D3KooWResponder123456789")

	// Initiator wants someone who wants children
	initiatorQuestions := [3]DealBreaker{
		{Question: "Do you want children?", Answer: true},
		{Question: "Are you a smoker?", Answer: false},
		{Question: "Do you live in Europe?", Answer: true},
	}

	// Responder does NOT want children - this is a deal-breaker
	responderAnswers := [3]bool{false, false, true}

	// Create the response
	responderResp := NewDealBreakerResponse(responderPeerID, responderAnswers, initiatorQuestions)

	// Verify the mismatch
	if CheckMatch(initiatorQuestions, responderResp.Answers) {
		t.Error("expected no match when responder doesn't want children")
	}
	if responderResp.Matched {
		t.Error("expected Matched to be false for mismatch")
	}
}

// ============================================================================
// Concurrent Tests
// ============================================================================

func TestDealBreakerConcurrentRequests(t *testing.T) {
	peerID := generateTestPeerID(t)
	questions := [3]DealBreaker{
		{Question: "Do you want children?", Answer: true},
		{Question: "Are you a smoker?", Answer: false},
		{Question: "Do you live in Europe?", Answer: true},
	}

	var wg sync.WaitGroup
	numGoroutines := 10
	requests := make([]*DealBreakerRequest, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			requests[idx] = NewDealBreakerRequest(peerID, questions)
		}(i)
	}

	wg.Wait()

	// All requests should have been created successfully
	for i, req := range requests {
		if req == nil {
			t.Errorf("request %d is nil", i)
			continue
		}
		if req.PeerID != peerID {
			t.Errorf("request %d has wrong peerID", i)
		}
		if req.Questions != questions {
			t.Errorf("request %d has wrong questions", i)
		}
	}
}

func TestDealBreakerConcurrentResponses(t *testing.T) {
	peerID := generateTestPeerID(t)
	peerQuestions := [3]DealBreaker{
		{Question: "Are you religious?", Answer: true},
		{Question: "Do you have pets?", Answer: true},
		{Question: "Are you a morning person?", Answer: false},
	}
	myAnswers := [3]bool{true, true, false}

	var wg sync.WaitGroup
	numGoroutines := 10
	responses := make([]*DealBreakerResponse, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			responses[idx] = NewDealBreakerResponse(peerID, myAnswers, peerQuestions)
		}(i)
	}

	wg.Wait()

	// All responses should have been created successfully
	for i, resp := range responses {
		if resp == nil {
			t.Errorf("response %d is nil", i)
			continue
		}
		if resp.PeerID != peerID {
			t.Errorf("response %d has wrong peerID", i)
		}
		if resp.Answers != myAnswers {
			t.Errorf("response %d has wrong answers", i)
		}
		if !resp.Matched {
			t.Errorf("response %d should have Matched=true", i)
		}
	}
}

func TestDealBreakerConcurrentSignAndVerify(t *testing.T) {
	peerID := generateTestPeerID(t)
	pub, priv := generateTestKeyPair(t)
	questions := [3]DealBreaker{
		{Question: "Do you want children?", Answer: true},
		{Question: "Are you a smoker?", Answer: false},
		{Question: "Do you live in Europe?", Answer: true},
	}

	var wg sync.WaitGroup
	numGoroutines := 10
	errors := make([]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := NewDealBreakerRequest(peerID, questions)
			if err := req.Sign(priv); err != nil {
				errors[idx] = err
				return
			}
			if err := req.Verify(pub); err != nil {
				errors[idx] = err
				return
			}
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Errorf("goroutine %d failed: %v", i, err)
		}
	}
}

// ============================================================================
// Serialization Tests (for bytes to sign)
// ============================================================================

func TestDealBreakerRequestBytesToSign(t *testing.T) {
	peerID := generateTestPeerID(t)
	questions := [3]DealBreaker{
		{Question: "Do you want children?", Answer: true},
		{Question: "Are you a smoker?", Answer: false},
		{Question: "Do you live in Europe?", Answer: true},
	}

	req := NewDealBreakerRequest(peerID, questions)

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

func TestDealBreakerResponseBytesToSign(t *testing.T) {
	peerID := generateTestPeerID(t)
	peerQuestions := [3]DealBreaker{
		{Question: "Are you religious?", Answer: true},
		{Question: "Do you have pets?", Answer: true},
		{Question: "Are you a morning person?", Answer: false},
	}
	myAnswers := [3]bool{true, true, false}

	resp := NewDealBreakerResponse(peerID, myAnswers, peerQuestions)

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

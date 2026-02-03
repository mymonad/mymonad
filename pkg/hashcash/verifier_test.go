// Package hashcash provides Proof-of-Work mining and verification for anti-spam.
package hashcash

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"github.com/mymonad/mymonad/api/proto"
)

// =============================================================================
// Verify Tests - Valid Solution
// =============================================================================

func TestVerify_AcceptsValidSolution(t *testing.T) {
	// Arrange: Create a challenge and mine a valid solution
	challenge := &proto.PoWChallenge{
		Nonce:      makeTestNonce(16),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 16,
		PeerId:     []byte("verifier-peer"),
	}
	proverPeerID := []byte("prover-peer")

	miner := NewMiner(1 << 24)
	result, err := miner.Mine(challenge, proverPeerID)
	if err != nil {
		t.Fatalf("failed to mine solution: %v", err)
	}

	solution := &proto.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	// Act
	err = Verify(challenge, solution, proverPeerID)

	// Assert
	if err != nil {
		t.Errorf("Verify should accept valid solution, got error: %v", err)
	}
}

func TestVerify_AcceptsValidSolutionWithHigherDifficulty(t *testing.T) {
	// A solution that exceeds the required difficulty should still be valid
	challenge := &proto.PoWChallenge{
		Nonce:      makeTestNonce(16),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 12, // Lower difficulty
		PeerId:     []byte("verifier"),
	}
	proverPeerID := []byte("prover")

	// Mine at higher difficulty (16 bits)
	miner := NewMiner(1 << 24)
	// Use a challenge with higher difficulty for mining, then verify against lower
	highDiffChallenge := &proto.PoWChallenge{
		Nonce:      challenge.Nonce,
		Timestamp:  challenge.Timestamp,
		Difficulty: 16, // Higher difficulty
		PeerId:     challenge.PeerId,
	}

	result, err := miner.Mine(highDiffChallenge, proverPeerID)
	if err != nil {
		t.Fatalf("failed to mine: %v", err)
	}

	solution := &proto.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	// Verify against the lower difficulty challenge
	err = Verify(challenge, solution, proverPeerID)
	if err != nil {
		t.Errorf("should accept solution that exceeds required difficulty: %v", err)
	}
}

// =============================================================================
// Verify Tests - Nonce Mismatch
// =============================================================================

func TestVerify_RejectsNonceMismatch(t *testing.T) {
	challenge := &proto.PoWChallenge{
		Nonce:      makeTestNonce(16),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 16,
		PeerId:     []byte("verifier"),
	}
	proverPeerID := []byte("prover")

	miner := NewMiner(1 << 24)
	result, err := miner.Mine(challenge, proverPeerID)
	if err != nil {
		t.Fatalf("failed to mine: %v", err)
	}

	// Create solution with different nonce
	differentNonce := make([]byte, 16)
	copy(differentNonce, challenge.Nonce)
	differentNonce[0] ^= 0xFF // Flip bits in first byte

	solution := &proto.PoWSolution{
		ChallengeNonce:     differentNonce, // WRONG NONCE
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	err = Verify(challenge, solution, proverPeerID)
	if err == nil {
		t.Error("Verify should reject nonce mismatch")
	}
	if err != nil && err != ErrNonceMismatch {
		t.Errorf("expected ErrNonceMismatch, got: %v", err)
	}
}

func TestVerify_RejectsEmptyNonce(t *testing.T) {
	challenge := &proto.PoWChallenge{
		Nonce:      makeTestNonce(16),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 16,
		PeerId:     []byte("verifier"),
	}
	proverPeerID := []byte("prover")

	miner := NewMiner(1 << 24)
	result, err := miner.Mine(challenge, proverPeerID)
	if err != nil {
		t.Fatalf("failed to mine: %v", err)
	}

	solution := &proto.PoWSolution{
		ChallengeNonce:     []byte{}, // EMPTY NONCE
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	err = Verify(challenge, solution, proverPeerID)
	if err == nil {
		t.Error("Verify should reject empty nonce")
	}
}

// =============================================================================
// Verify Tests - Timestamp Mismatch
// =============================================================================

func TestVerify_RejectsTimestampMismatch(t *testing.T) {
	challenge := &proto.PoWChallenge{
		Nonce:      makeTestNonce(16),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 16,
		PeerId:     []byte("verifier"),
	}
	proverPeerID := []byte("prover")

	miner := NewMiner(1 << 24)
	result, err := miner.Mine(challenge, proverPeerID)
	if err != nil {
		t.Fatalf("failed to mine: %v", err)
	}

	solution := &proto.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp + 1000, // WRONG TIMESTAMP
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	err = Verify(challenge, solution, proverPeerID)
	if err == nil {
		t.Error("Verify should reject timestamp mismatch")
	}
	if err != nil && err != ErrTimestampMismatch {
		t.Errorf("expected ErrTimestampMismatch, got: %v", err)
	}
}

func TestVerify_RejectsZeroTimestamp(t *testing.T) {
	challenge := &proto.PoWChallenge{
		Nonce:      makeTestNonce(16),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 16,
		PeerId:     []byte("verifier"),
	}
	proverPeerID := []byte("prover")

	miner := NewMiner(1 << 24)
	result, err := miner.Mine(challenge, proverPeerID)
	if err != nil {
		t.Fatalf("failed to mine: %v", err)
	}

	solution := &proto.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: 0, // ZERO TIMESTAMP
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	err = Verify(challenge, solution, proverPeerID)
	if err == nil {
		t.Error("Verify should reject zero timestamp")
	}
}

// =============================================================================
// Verify Tests - Hash Mismatch (Tampered Proof)
// =============================================================================

func TestVerify_RejectsTamperedProof(t *testing.T) {
	challenge := &proto.PoWChallenge{
		Nonce:      makeTestNonce(16),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 16,
		PeerId:     []byte("verifier"),
	}
	proverPeerID := []byte("prover")

	miner := NewMiner(1 << 24)
	result, err := miner.Mine(challenge, proverPeerID)
	if err != nil {
		t.Fatalf("failed to mine: %v", err)
	}

	// Tamper with the proof
	tamperedProof := make([]byte, len(result.Proof))
	copy(tamperedProof, result.Proof)
	tamperedProof[15] ^= 0xFF // Flip bits

	solution := &proto.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              tamperedProof, // TAMPERED PROOF
	}

	err = Verify(challenge, solution, proverPeerID)
	if err == nil {
		t.Error("Verify should reject tampered proof")
	}
	if err != nil && err != ErrHashMismatch {
		t.Errorf("expected ErrHashMismatch, got: %v", err)
	}
}

func TestVerify_RejectsEmptyProof(t *testing.T) {
	challenge := &proto.PoWChallenge{
		Nonce:      makeTestNonce(16),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 16,
		PeerId:     []byte("verifier"),
	}
	proverPeerID := []byte("prover")

	miner := NewMiner(1 << 24)
	result, err := miner.Mine(challenge, proverPeerID)
	if err != nil {
		t.Fatalf("failed to mine: %v", err)
	}

	solution := &proto.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              []byte{}, // EMPTY PROOF
	}

	err = Verify(challenge, solution, proverPeerID)
	if err == nil {
		t.Error("Verify should reject empty proof")
	}
}

func TestVerify_RejectsWrongLengthProof(t *testing.T) {
	challenge := &proto.PoWChallenge{
		Nonce:      makeTestNonce(16),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 16,
		PeerId:     []byte("verifier"),
	}
	proverPeerID := []byte("prover")

	miner := NewMiner(1 << 24)
	result, err := miner.Mine(challenge, proverPeerID)
	if err != nil {
		t.Fatalf("failed to mine: %v", err)
	}

	// Create proof with wrong length (should be 32 bytes for SHA-256)
	shortProof := result.Proof[:16]

	solution := &proto.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              shortProof, // WRONG LENGTH
	}

	err = Verify(challenge, solution, proverPeerID)
	if err == nil {
		t.Error("Verify should reject wrong length proof")
	}
}

// =============================================================================
// Verify Tests - Wrong Peer ID
// =============================================================================

func TestVerify_RejectsWrongPeerID(t *testing.T) {
	challenge := &proto.PoWChallenge{
		Nonce:      makeTestNonce(16),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 16,
		PeerId:     []byte("verifier"),
	}
	proverPeerID := []byte("prover")

	miner := NewMiner(1 << 24)
	result, err := miner.Mine(challenge, proverPeerID)
	if err != nil {
		t.Fatalf("failed to mine: %v", err)
	}

	solution := &proto.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	// Verify with WRONG peer ID
	wrongPeerID := []byte("wrong-prover")
	err = Verify(challenge, solution, wrongPeerID)
	if err == nil {
		t.Error("Verify should reject wrong peer ID")
	}
	if err != nil && err != ErrHashMismatch {
		t.Errorf("expected ErrHashMismatch (because hash won't match with wrong peer ID), got: %v", err)
	}
}

func TestVerify_RejectsEmptyPeerID(t *testing.T) {
	challenge := &proto.PoWChallenge{
		Nonce:      makeTestNonce(16),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 16,
		PeerId:     []byte("verifier"),
	}
	proverPeerID := []byte("prover")

	miner := NewMiner(1 << 24)
	result, err := miner.Mine(challenge, proverPeerID)
	if err != nil {
		t.Fatalf("failed to mine: %v", err)
	}

	solution := &proto.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	// Verify with empty peer ID
	err = Verify(challenge, solution, []byte{})
	if err == nil {
		t.Error("Verify should reject empty peer ID (hash won't match)")
	}
}

// =============================================================================
// Verify Tests - Insufficient Difficulty
// =============================================================================

func TestVerify_RejectsInsufficientDifficulty(t *testing.T) {
	// Mine at lower difficulty
	lowDiffChallenge := &proto.PoWChallenge{
		Nonce:      makeTestNonce(16),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 8, // Low difficulty
		PeerId:     []byte("verifier"),
	}
	proverPeerID := []byte("prover")

	miner := NewMiner(1 << 20)
	result, err := miner.Mine(lowDiffChallenge, proverPeerID)
	if err != nil {
		t.Fatalf("failed to mine: %v", err)
	}

	// Verify the solution does NOT meet higher difficulty
	leadingZeros := countLeadingZeroBits(result.Proof)
	if leadingZeros >= 16 {
		t.Skip("solution happens to meet higher difficulty, skipping test")
	}

	// Create a challenge that requires higher difficulty
	highDiffChallenge := &proto.PoWChallenge{
		Nonce:      lowDiffChallenge.Nonce,
		Timestamp:  lowDiffChallenge.Timestamp,
		Difficulty: 16, // Higher difficulty
		PeerId:     lowDiffChallenge.PeerId,
	}

	solution := &proto.PoWSolution{
		ChallengeNonce:     lowDiffChallenge.Nonce,
		ChallengeTimestamp: lowDiffChallenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	err = Verify(highDiffChallenge, solution, proverPeerID)
	if err == nil {
		t.Error("Verify should reject solution with insufficient difficulty")
	}
	if err != nil && err != ErrInsufficientDifficulty {
		t.Errorf("expected ErrInsufficientDifficulty, got: %v", err)
	}
}

func TestVerify_RejectsFakeProofWithLeadingZeros(t *testing.T) {
	// Create a fake proof that has leading zeros but doesn't match the hash
	challenge := &proto.PoWChallenge{
		Nonce:      makeTestNonce(16),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 16,
		PeerId:     []byte("verifier"),
	}
	proverPeerID := []byte("prover")

	// Create a fake proof with lots of leading zeros
	fakeProof := make([]byte, 32)
	// First bytes are zero, so it would pass difficulty check alone
	// But the hash won't match

	solution := &proto.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            12345, // Arbitrary counter
		Proof:              fakeProof,
	}

	err := Verify(challenge, solution, proverPeerID)
	if err == nil {
		t.Error("Verify should reject fake proof even if it has leading zeros")
	}
}

// =============================================================================
// Verify Tests - Nil/Empty Inputs
// =============================================================================

func TestVerify_RejectsNilChallenge(t *testing.T) {
	solution := &proto.PoWSolution{
		ChallengeNonce:     makeTestNonce(16),
		ChallengeTimestamp: time.Now().UnixMilli(),
		Counter:            1234,
		Proof:              make([]byte, 32),
	}

	err := Verify(nil, solution, []byte("prover"))
	if err == nil {
		t.Error("Verify should reject nil challenge")
	}
	if err != nil && err != ErrNilChallenge {
		t.Errorf("expected ErrNilChallenge, got: %v", err)
	}
}

func TestVerify_RejectsNilSolution(t *testing.T) {
	challenge := &proto.PoWChallenge{
		Nonce:      makeTestNonce(16),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 16,
		PeerId:     []byte("verifier"),
	}

	err := Verify(challenge, nil, []byte("prover"))
	if err == nil {
		t.Error("Verify should reject nil solution")
	}
	if err != nil && err != ErrNilSolution {
		t.Errorf("expected ErrNilSolution, got: %v", err)
	}
}

// =============================================================================
// Integration Test - Mine and Verify
// =============================================================================

func TestVerify_IntegrationWithMiner(t *testing.T) {
	difficulties := []uint32{8, 12, 16}

	for _, difficulty := range difficulties {
		t.Run("difficulty_"+string(rune('0'+difficulty/10))+string(rune('0'+difficulty%10)), func(t *testing.T) {
			challenge := &proto.PoWChallenge{
				Nonce:      makeTestNonce(16),
				Timestamp:  time.Now().UnixMilli(),
				Difficulty: difficulty,
				PeerId:     []byte("verifier-peer-12345"),
			}
			proverPeerID := []byte("prover-peer-67890")

			miner := NewMiner(1 << 26)
			result, err := miner.Mine(challenge, proverPeerID)
			if err != nil {
				t.Fatalf("Mine failed: %v", err)
			}

			solution := &proto.PoWSolution{
				ChallengeNonce:     challenge.Nonce,
				ChallengeTimestamp: challenge.Timestamp,
				Counter:            result.Counter,
				Proof:              result.Proof,
			}

			err = Verify(challenge, solution, proverPeerID)
			if err != nil {
				t.Errorf("Verify failed for valid mined solution: %v", err)
			}
		})
	}
}

func TestVerify_ConsistentWithBuildPrefix(t *testing.T) {
	// Verify that our verification uses the same hash computation as mining
	challenge := &proto.PoWChallenge{
		Nonce:      []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
		Timestamp:  1706745600000,
		Difficulty: 16,
		PeerId:     []byte("verifier"),
	}
	proverPeerID := []byte("prover")
	counter := uint64(12345)

	// Manually compute expected hash
	prefix := buildPrefix(challenge.Nonce, challenge.Timestamp, proverPeerID)
	counterBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBuf, counter)
	expectedHash := sha256.Sum256(append(prefix, counterBuf...))

	// Create solution with the computed hash
	solution := &proto.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            counter,
		Proof:              expectedHash[:],
	}

	// Verify should accept if difficulty is met
	// The hash may or may not meet difficulty 16, so we check for expected error
	err := Verify(challenge, solution, proverPeerID)

	// If difficulty is not met, we should get ErrInsufficientDifficulty
	// If difficulty is met, err should be nil
	// But we should NOT get ErrHashMismatch since we computed the hash correctly
	if err == ErrHashMismatch {
		t.Error("Hash should match when computed using same algorithm as buildPrefix")
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkVerifyValidSolution(b *testing.B) {
	challenge := &proto.PoWChallenge{
		Nonce:      makeTestNonce(16),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 16,
		PeerId:     []byte("verifier"),
	}
	proverPeerID := []byte("prover")

	miner := NewMiner(1 << 24)
	result, err := miner.Mine(challenge, proverPeerID)
	if err != nil {
		b.Fatalf("failed to mine: %v", err)
	}

	solution := &proto.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Verify(challenge, solution, proverPeerID)
	}
}

func BenchmarkVerifyNonceMismatch(b *testing.B) {
	challenge := &proto.PoWChallenge{
		Nonce:      makeTestNonce(16),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 16,
		PeerId:     []byte("verifier"),
	}

	wrongNonce := make([]byte, 16)
	copy(wrongNonce, challenge.Nonce)
	wrongNonce[0] ^= 0xFF

	solution := &proto.PoWSolution{
		ChallengeNonce:     wrongNonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            12345,
		Proof:              make([]byte, 32),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Verify(challenge, solution, []byte("prover"))
	}
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestVerify_LargePeerID(t *testing.T) {
	challenge := &proto.PoWChallenge{
		Nonce:      makeTestNonce(16),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 8, // Low difficulty for fast test
		PeerId:     []byte("verifier"),
	}

	// Large peer ID (1KB)
	largePeerID := bytes.Repeat([]byte("a"), 1024)

	miner := NewMiner(1 << 20)
	result, err := miner.Mine(challenge, largePeerID)
	if err != nil {
		t.Fatalf("failed to mine: %v", err)
	}

	solution := &proto.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	err = Verify(challenge, solution, largePeerID)
	if err != nil {
		t.Errorf("Verify should accept valid solution with large peer ID: %v", err)
	}
}

func TestVerify_ZeroDifficulty(t *testing.T) {
	challenge := &proto.PoWChallenge{
		Nonce:      makeTestNonce(16),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 0, // Zero difficulty
		PeerId:     []byte("verifier"),
	}
	proverPeerID := []byte("prover")

	miner := NewMiner(1 << 20)
	result, err := miner.Mine(challenge, proverPeerID)
	if err != nil {
		t.Fatalf("failed to mine: %v", err)
	}

	solution := &proto.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	err = Verify(challenge, solution, proverPeerID)
	// Zero difficulty uses target[0]=0x80, so most hashes will fail
	// But if miner found a solution, Verify should accept it
	if err != nil {
		t.Errorf("Verify should accept mined solution even with zero difficulty: %v", err)
	}
}

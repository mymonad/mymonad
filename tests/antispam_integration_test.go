// Package tests contains integration tests for the anti-spam system.
// These tests verify the complete challenge-response workflow, including
// difficulty escalation, replay attack prevention, and challenge expiration.
package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/mymonad/mymonad/api/proto"
	"github.com/mymonad/mymonad/internal/antispam"
	"github.com/mymonad/mymonad/pkg/hashcash"
)

// TestAntiSpam_FullChallengeResponse tests the complete challenge-response workflow.
// It verifies that:
// 1. A challenge can be issued for a peer
// 2. The challenge can be mined to find a valid solution
// 3. The solution can be verified successfully
func TestAntiSpam_FullChallengeResponse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	service := antispam.NewAntiSpamService(antispam.DefaultDifficultyConfig())
	defer service.Stop()

	proverID := peer.ID("prover-peer")

	// Step 1: Issue challenge
	challenge, err := service.IssueChallenge(proverID)
	require.NoError(t, err, "IssueChallenge should succeed")
	require.NotNil(t, challenge, "Challenge should not be nil")

	// Verify challenge fields
	assert.Len(t, challenge.Nonce, antispam.NonceLength, "Nonce should be %d bytes", antispam.NonceLength)
	assert.NotZero(t, challenge.Timestamp, "Timestamp should be set")
	assert.Equal(t, antispam.TierNormal.Bits(), challenge.Difficulty, "Initial difficulty should be Normal tier")
	assert.Equal(t, []byte(proverID), challenge.PeerId, "PeerId should match prover")

	// Step 2: Mine solution
	// Using 1<<24 iterations should be sufficient for 16-bit difficulty
	miner := hashcash.NewMiner(1 << 24)
	result, err := miner.Mine(challenge, []byte(proverID))
	require.NoError(t, err, "Mining should succeed")
	require.NotNil(t, result, "Mine result should not be nil")

	t.Logf("Mining completed in %v with counter %d", result.Elapsed, result.Counter)

	// Step 3: Create solution
	solution := &pb.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	// Step 4: Verify solution
	err = service.VerifyResponse(challenge, solution, proverID)
	require.NoError(t, err, "VerifyResponse should succeed for valid solution")

	// Verify service state remains Normal after successful verification
	assert.Equal(t, antispam.TierNormal, service.GetCurrentTier(), "Tier should remain Normal after success")
}

// TestAntiSpam_DifficultyEscalationUnderLoad tests that difficulty escalates under attack.
// It verifies that:
// 1. The service starts at Normal tier
// 2. Multiple failures cause the tier to escalate
// 3. The final tier is higher than Normal
func TestAntiSpam_DifficultyEscalationUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Configure with low thresholds to make escalation easier to trigger
	config := &antispam.DifficultyConfig{
		WindowDuration:        1 * time.Minute,
		CooldownDuration:      5 * time.Minute,
		ElevatedRateThreshold: 100,  // High rate threshold (don't trigger on rate)
		ElevatedFailureRate:   0.20, // 20% failure rate triggers escalation
		HighRateThreshold:     500,
		HighFailureRate:       0.40,
		CriticalRateThreshold: 1000,
		CriticalFailureRate:   0.60,
	}

	service := antispam.NewAntiSpamService(config)
	defer service.Stop()

	// Verify starts at Normal
	require.Equal(t, antispam.TierNormal, service.GetCurrentTier(), "Initial tier should be Normal")

	// Simulate spam attack (many failures)
	// We need enough failures to exceed the 20% failure rate threshold
	for i := 0; i < 20; i++ {
		attackerID := peer.ID(fmt.Sprintf("attacker-%d", i))
		challenge, err := service.IssueChallenge(attackerID)
		require.NoError(t, err, "IssueChallenge should succeed")

		// Submit invalid solution (will fail verification)
		badSolution := &pb.PoWSolution{
			ChallengeNonce:     challenge.Nonce,
			ChallengeTimestamp: challenge.Timestamp,
			Counter:            0,
			Proof:              []byte("invalid-proof-that-will-fail"),
		}

		// This should fail, which records a failure
		err = service.VerifyResponse(challenge, badSolution, attackerID)
		assert.Error(t, err, "Bad solution should be rejected")
	}

	// Should have escalated due to high failure rate
	tier := service.GetCurrentTier()
	assert.Greater(t, tier, antispam.TierNormal,
		"Tier should have escalated above Normal after many failures, got: %s", tier)

	t.Logf("Tier escalated to: %s (bits: %d)", tier, tier.Bits())
}

// TestAntiSpam_ReplayAttackRejected tests that the same nonce cannot be used twice.
// This is a critical security property that prevents replay attacks.
// It verifies that:
// 1. A valid solution is accepted the first time
// 2. The same solution is rejected on the second attempt
// 3. The error message indicates nonce reuse
func TestAntiSpam_ReplayAttackRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	service := antispam.NewAntiSpamService(antispam.DefaultDifficultyConfig())
	defer service.Stop()

	proverID := peer.ID("prover-peer")

	// Step 1: Issue challenge
	challenge, err := service.IssueChallenge(proverID)
	require.NoError(t, err, "IssueChallenge should succeed")

	// Step 2: Mine solution
	miner := hashcash.NewMiner(1 << 24)
	result, err := miner.Mine(challenge, []byte(proverID))
	require.NoError(t, err, "Mining should succeed")

	// Step 3: Create solution
	solution := &pb.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	// Step 4: First verification should succeed
	err = service.VerifyResponse(challenge, solution, proverID)
	require.NoError(t, err, "First verification should succeed")

	// Step 5: Second verification (replay attack) should fail
	err = service.VerifyResponse(challenge, solution, proverID)
	require.Error(t, err, "Second verification (replay) should fail")
	assert.Contains(t, err.Error(), "nonce",
		"Error should indicate nonce issue (already used)")

	t.Logf("Replay attack correctly rejected with error: %v", err)
}

// TestAntiSpam_ExpiredChallengeRejected tests that expired challenges are rejected.
// This test uses the NonceStore directly with a very short expiration to avoid
// long wait times, since the service's expiration is tied to difficulty tiers
// (30-120 seconds).
//
// It verifies that:
// 1. A challenge with very short expiration can be generated
// 2. After expiration, validation fails with appropriate error
func TestAntiSpam_ExpiredChallengeRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Test expiration using NonceStore directly with very short expiration
	// This allows us to test expiration logic without waiting 30+ seconds
	// Use a long cleanup interval to prevent the cleanup loop from removing
	// the expired nonce before we can test the expiration error
	store := antispam.NewNonceStoreWithCleanupInterval(10 * time.Second)
	defer store.Stop()

	proverID := peer.ID("prover-peer")
	difficulty := uint32(16)
	shortExpiration := 50 * time.Millisecond // Very short expiration for testing

	// Generate a challenge with short expiration
	challenge, err := store.GenerateChallenge(proverID, difficulty, shortExpiration)
	require.NoError(t, err, "GenerateChallenge should succeed")
	require.NotNil(t, challenge, "Challenge should not be nil")

	// Wait for expiration (but not long enough for cleanup to run)
	time.Sleep(100 * time.Millisecond)

	// Try to validate the expired nonce
	// The nonce should still be in the store (cleanup hasn't run) but marked as expired
	record, err := store.ValidateAndConsume(challenge.Nonce, proverID)
	require.Error(t, err, "Validation should fail for expired nonce")
	require.Nil(t, record, "Record should be nil for expired nonce")
	assert.Equal(t, antispam.ErrNonceExpired, err, "Error should be ErrNonceExpired")

	t.Logf("Expired challenge correctly rejected with error: %v", err)
}

// TestAntiSpam_ServiceExpirationCheck tests expiration check within the full service.
// This complements TestAntiSpam_ExpiredChallengeRejected by testing the timestamp
// check in VerifyResponse, not just the nonce store expiration.
func TestAntiSpam_ServiceExpirationCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	service := antispam.NewAntiSpamService(antispam.DefaultDifficultyConfig())
	defer service.Stop()

	proverID := peer.ID("prover-peer")

	// Issue a valid challenge
	challenge, err := service.IssueChallenge(proverID)
	require.NoError(t, err, "IssueChallenge should succeed")

	// Mine a valid solution
	miner := hashcash.NewMiner(1 << 24)
	result, err := miner.Mine(challenge, []byte(proverID))
	require.NoError(t, err, "Mining should succeed")

	// Create a modified challenge with an old timestamp
	// This simulates an attacker trying to use a challenge after expiration
	oldChallenge := &pb.PoWChallenge{
		Nonce:      challenge.Nonce,
		Timestamp:  time.Now().Add(-2 * time.Minute).UnixMilli(), // 2 minutes ago
		Difficulty: challenge.Difficulty,
		PeerId:     challenge.PeerId,
	}

	// Create solution referencing the old challenge
	solution := &pb.PoWSolution{
		ChallengeNonce:     oldChallenge.Nonce,
		ChallengeTimestamp: oldChallenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	// Verification should fail due to expired timestamp
	err = service.VerifyResponse(oldChallenge, solution, proverID)
	require.Error(t, err, "Verification should fail for challenge with old timestamp")
	assert.Contains(t, err.Error(), "expired",
		"Error should indicate expiration issue")

	t.Logf("Expired timestamp correctly rejected with error: %v", err)
}

// TestAntiSpam_ConcurrentChallenges tests that the service handles concurrent
// challenge-response flows correctly.
func TestAntiSpam_ConcurrentChallenges(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	service := antispam.NewAntiSpamService(antispam.DefaultDifficultyConfig())
	defer service.Stop()

	const numConcurrent = 10
	done := make(chan bool, numConcurrent)
	errors := make(chan error, numConcurrent)

	// Launch concurrent challenge-response flows
	for i := 0; i < numConcurrent; i++ {
		go func(id int) {
			proverID := peer.ID(fmt.Sprintf("prover-%d", id))

			// Issue challenge
			challenge, err := service.IssueChallenge(proverID)
			if err != nil {
				errors <- fmt.Errorf("prover %d: IssueChallenge failed: %w", id, err)
				done <- false
				return
			}

			// Mine solution (use lower iterations for concurrent tests)
			miner := hashcash.NewMiner(1 << 20)
			result, err := miner.Mine(challenge, []byte(proverID))
			if err != nil {
				errors <- fmt.Errorf("prover %d: Mining failed: %w", id, err)
				done <- false
				return
			}

			// Create and verify solution
			solution := &pb.PoWSolution{
				ChallengeNonce:     challenge.Nonce,
				ChallengeTimestamp: challenge.Timestamp,
				Counter:            result.Counter,
				Proof:              result.Proof,
			}

			if err := service.VerifyResponse(challenge, solution, proverID); err != nil {
				errors <- fmt.Errorf("prover %d: VerifyResponse failed: %w", id, err)
				done <- false
				return
			}

			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	successCount := 0
	for i := 0; i < numConcurrent; i++ {
		success := <-done
		if success {
			successCount++
		}
	}

	// Check for any errors
	close(errors)
	for err := range errors {
		t.Errorf("Concurrent test error: %v", err)
	}

	assert.Equal(t, numConcurrent, successCount,
		"All concurrent challenge-response flows should succeed")
}

// TestAntiSpam_TierDeescalation tests that difficulty de-escalates after cooldown.
// This test uses the DifficultyController directly to verify de-escalation logic
// without needing to mine high-difficulty challenges.
func TestAntiSpam_TierDeescalation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Use very short cooldown and window for testing
	config := &antispam.DifficultyConfig{
		WindowDuration:        200 * time.Millisecond,
		CooldownDuration:      100 * time.Millisecond, // Very short cooldown for testing
		ElevatedRateThreshold: 100,                    // High rate threshold
		ElevatedFailureRate:   0.30,                   // 30% failure triggers escalation
		HighRateThreshold:     500,
		HighFailureRate:       0.50,
		CriticalRateThreshold: 1000,
		CriticalFailureRate:   0.70,
	}

	// Create a controller directly to test de-escalation without mining
	controller := antispam.NewDifficultyController(config)

	// Record failures to escalate the tier
	for i := 0; i < 10; i++ {
		controller.RecordChallenge(false) // All failures
	}

	escalatedTier := controller.GetCurrentTier()
	require.Greater(t, escalatedTier, antispam.TierNormal,
		"Tier should have escalated after failures")

	t.Logf("Tier escalated to: %s", escalatedTier)

	// Wait for window to expire (challenges become stale)
	time.Sleep(300 * time.Millisecond)

	// Record successful challenges to trigger de-escalation
	// After window expires, all previous failures are gone
	// New successes should trigger de-escalation after cooldown
	for i := 0; i < 5; i++ {
		time.Sleep(150 * time.Millisecond) // Wait for cooldown between each
		controller.RecordChallenge(true)   // Success
	}

	finalTier := controller.GetCurrentTier()
	t.Logf("Final tier after de-escalation: %s", finalTier)

	// The tier should have de-escalated
	assert.Less(t, finalTier, escalatedTier,
		"Tier should have de-escalated after cooldown and successful challenges")
}

// TestAntiSpam_WrongPeerRejection tests that solutions are bound to specific peers.
func TestAntiSpam_WrongPeerRejection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	service := antispam.NewAntiSpamService(antispam.DefaultDifficultyConfig())
	defer service.Stop()

	originalPeer := peer.ID("original-peer")
	wrongPeer := peer.ID("wrong-peer")

	// Issue challenge for original peer
	challenge, err := service.IssueChallenge(originalPeer)
	require.NoError(t, err, "IssueChallenge should succeed")

	// Mine solution (using wrong peer's ID, which will produce different hash)
	miner := hashcash.NewMiner(1 << 24)
	result, err := miner.Mine(challenge, []byte(wrongPeer))
	require.NoError(t, err, "Mining should succeed")

	solution := &pb.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	// Verification should fail because wrong peer is trying to use the solution
	err = service.VerifyResponse(challenge, solution, wrongPeer)
	require.Error(t, err, "Verification should fail for wrong peer")
	assert.Contains(t, err.Error(), "nonce",
		"Error should indicate nonce validation failed (bound to different peer)")

	t.Logf("Wrong peer correctly rejected with error: %v", err)
}

// TestAntiSpam_TierChangeCallback tests that callbacks are invoked on tier changes.
func TestAntiSpam_TierChangeCallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	config := &antispam.DifficultyConfig{
		WindowDuration:        1 * time.Minute,
		CooldownDuration:      5 * time.Minute,
		ElevatedRateThreshold: 100,
		ElevatedFailureRate:   0.15, // Low threshold to trigger easily
		HighRateThreshold:     500,
		HighFailureRate:       0.35,
		CriticalRateThreshold: 1000,
		CriticalFailureRate:   0.55,
	}

	service := antispam.NewAntiSpamService(config)
	defer service.Stop()

	// Track tier changes
	var tierChanges []antispam.DifficultyTier
	service.SetOnTierChange(func(tier antispam.DifficultyTier) {
		tierChanges = append(tierChanges, tier)
		t.Logf("Tier changed to: %s", tier)
	})

	// Cause failures to trigger tier change
	for i := 0; i < 15; i++ {
		attackerID := peer.ID(fmt.Sprintf("attacker-%d", i))
		challenge, err := service.IssueChallenge(attackerID)
		require.NoError(t, err)

		badSolution := &pb.PoWSolution{
			ChallengeNonce:     challenge.Nonce,
			ChallengeTimestamp: challenge.Timestamp,
			Counter:            0,
			Proof:              []byte("invalid"),
		}
		_ = service.VerifyResponse(challenge, badSolution, attackerID)
	}

	// Should have recorded tier changes
	assert.NotEmpty(t, tierChanges,
		"Should have recorded tier changes during attack simulation")

	// Verify the tier changes were to higher tiers
	for _, tier := range tierChanges {
		assert.Greater(t, tier, antispam.TierNormal,
			"All tier changes should be to tiers above Normal")
	}
}

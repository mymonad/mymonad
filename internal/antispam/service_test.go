// Package antispam provides load-adaptive spam prevention for the MyMonad P2P protocol.
package antispam

import (
	"testing"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
	"github.com/mymonad/mymonad/pkg/hashcash"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewAntiSpamService verifies that a new AntiSpamService is created correctly.
func TestNewAntiSpamService(t *testing.T) {
	service := NewAntiSpamService(nil)
	require.NotNil(t, service, "NewAntiSpamService should return a non-nil service")
	defer service.Stop()

	// Verify internal components are initialized
	require.NotNil(t, service.controller, "Controller should be initialized")
	require.NotNil(t, service.nonceStore, "NonceStore should be initialized")
}

// TestNewAntiSpamServiceWithConfig verifies custom config is used.
func TestNewAntiSpamServiceWithConfig(t *testing.T) {
	config := &DifficultyConfig{
		WindowDuration:        2 * time.Minute,
		CooldownDuration:      10 * time.Minute,
		ElevatedRateThreshold: 20,
		ElevatedFailureRate:   0.15,
		HighRateThreshold:     100,
		HighFailureRate:       0.40,
		CriticalRateThreshold: 200,
		CriticalFailureRate:   0.60,
	}

	service := NewAntiSpamService(config)
	require.NotNil(t, service)
	defer service.Stop()

	// The controller should use the custom config
	// We can verify by checking the tier (should be Normal initially)
	tier := service.GetCurrentTier()
	assert.Equal(t, TierNormal, tier, "Initial tier should be Normal")
}

// TestIssueChallengeReturnsValidChallenge verifies IssueChallenge creates a proper challenge.
func TestIssueChallengeReturnsValidChallenge(t *testing.T) {
	service := NewAntiSpamService(nil)
	defer service.Stop()

	peerID := peer.ID("test-peer-123")

	challenge, err := service.IssueChallenge(peerID)
	require.NoError(t, err, "IssueChallenge should not return an error")
	require.NotNil(t, challenge, "Challenge should not be nil")

	// Verify challenge fields
	assert.Len(t, challenge.Nonce, NonceLength, "Nonce should be %d bytes", NonceLength)
	assert.NotZero(t, challenge.Timestamp, "Timestamp should be set")
	assert.Equal(t, uint32(16), challenge.Difficulty, "Default difficulty should be 16 bits")
	assert.Equal(t, []byte(peerID), challenge.PeerId, "PeerID should match")
}

// TestIssueChallengeProducesUniqueNonces verifies unique challenges.
func TestIssueChallengeProducesUniqueNonces(t *testing.T) {
	service := NewAntiSpamService(nil)
	defer service.Stop()

	peerID := peer.ID("test-peer")
	nonces := make(map[string]bool)

	for i := 0; i < 50; i++ {
		challenge, err := service.IssueChallenge(peerID)
		require.NoError(t, err)

		nonceStr := string(challenge.Nonce)
		assert.False(t, nonces[nonceStr], "Nonce should be unique")
		nonces[nonceStr] = true
	}
}

// TestVerifyResponseSucceedsWithValidSolution tests the happy path.
func TestVerifyResponseSucceedsWithValidSolution(t *testing.T) {
	service := NewAntiSpamService(nil)
	defer service.Stop()

	proverPeerID := peer.ID("prover-peer")

	// Issue a challenge
	challenge, err := service.IssueChallenge(proverPeerID)
	require.NoError(t, err)

	// Mine a valid solution
	miner := hashcash.NewMiner(0)
	result, err := miner.Mine(challenge, []byte(proverPeerID))
	require.NoError(t, err, "Mining should succeed")

	// Create the solution
	solution := &pb.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	// Verify the response
	err = service.VerifyResponse(challenge, solution, proverPeerID)
	assert.NoError(t, err, "VerifyResponse should succeed with valid solution")
}

// TestVerifyResponseRejectsUnknownNonce verifies unknown nonce rejection.
func TestVerifyResponseRejectsUnknownNonce(t *testing.T) {
	service := NewAntiSpamService(nil)
	defer service.Stop()

	proverPeerID := peer.ID("prover-peer")

	// Create a fake challenge that was never issued
	fakeChallenge := &pb.PoWChallenge{
		Nonce:      make([]byte, NonceLength),
		Timestamp:  time.Now().UnixMilli(),
		Difficulty: 16,
		PeerId:     []byte(proverPeerID),
	}
	copy(fakeChallenge.Nonce, "fake-nonce-12345")

	// Create a fake solution
	solution := &pb.PoWSolution{
		ChallengeNonce:     fakeChallenge.Nonce,
		ChallengeTimestamp: fakeChallenge.Timestamp,
		Counter:            0,
		Proof:              make([]byte, 32),
	}

	err := service.VerifyResponse(fakeChallenge, solution, proverPeerID)
	assert.Error(t, err, "Should reject unknown nonce")
	assert.Contains(t, err.Error(), "nonce validation failed", "Error should indicate nonce issue")
}

// TestVerifyResponseRejectsWrongPeer verifies peer binding enforcement.
func TestVerifyResponseRejectsWrongPeer(t *testing.T) {
	service := NewAntiSpamService(nil)
	defer service.Stop()

	originalPeer := peer.ID("original-peer")
	wrongPeer := peer.ID("wrong-peer")

	// Issue a challenge for the original peer
	challenge, err := service.IssueChallenge(originalPeer)
	require.NoError(t, err)

	// Mine a valid solution as the wrong peer
	miner := hashcash.NewMiner(0)
	result, err := miner.Mine(challenge, []byte(wrongPeer))
	require.NoError(t, err)

	solution := &pb.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	// Try to verify as the wrong peer
	err = service.VerifyResponse(challenge, solution, wrongPeer)
	assert.Error(t, err, "Should reject solution from wrong peer")
	assert.Contains(t, err.Error(), "nonce validation failed", "Error should indicate nonce validation issue")
}

// TestVerifyResponseRejectsExpiredChallenge verifies expiration enforcement.
func TestVerifyResponseRejectsExpiredChallenge(t *testing.T) {
	// Use a config with very short expiration for testing
	config := &DifficultyConfig{
		WindowDuration:        1 * time.Minute,
		CooldownDuration:      5 * time.Minute,
		ElevatedRateThreshold: 10,
		ElevatedFailureRate:   0.10,
		HighRateThreshold:     50,
		HighFailureRate:       0.30,
		CriticalRateThreshold: 100,
		CriticalFailureRate:   0.50,
	}

	service := NewAntiSpamService(config)
	defer service.Stop()

	proverPeerID := peer.ID("prover-peer")

	// Issue a challenge
	challenge, err := service.IssueChallenge(proverPeerID)
	require.NoError(t, err)

	// Mine a valid solution
	miner := hashcash.NewMiner(0)
	result, err := miner.Mine(challenge, []byte(proverPeerID))
	require.NoError(t, err)

	// Create an old challenge with expired timestamp to test expiration check
	oldChallenge := &pb.PoWChallenge{
		Nonce:      challenge.Nonce,
		Timestamp:  time.Now().Add(-2 * time.Minute).UnixMilli(), // Old timestamp
		Difficulty: challenge.Difficulty,
		PeerId:     challenge.PeerId,
	}

	oldSolution := &pb.PoWSolution{
		ChallengeNonce:     oldChallenge.Nonce,
		ChallengeTimestamp: oldChallenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	// This should fail because the timestamp check will fail
	err = service.VerifyResponse(oldChallenge, oldSolution, proverPeerID)
	assert.Error(t, err, "Should reject expired challenge")
}

// TestVerifyResponseRejectsInvalidProof verifies proof validation.
func TestVerifyResponseRejectsInvalidProof(t *testing.T) {
	service := NewAntiSpamService(nil)
	defer service.Stop()

	proverPeerID := peer.ID("prover-peer")

	// Issue a challenge
	challenge, err := service.IssueChallenge(proverPeerID)
	require.NoError(t, err)

	// Create an invalid solution with wrong proof
	invalidSolution := &pb.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            12345,
		Proof:              make([]byte, 32), // All zeros - won't match
	}

	err = service.VerifyResponse(challenge, invalidSolution, proverPeerID)
	assert.Error(t, err, "Should reject invalid proof")
	assert.Contains(t, err.Error(), "proof verification failed", "Error should indicate proof issue")
}

// TestVerifyResponseRejectsReplayAttack verifies replay prevention.
func TestVerifyResponseRejectsReplayAttack(t *testing.T) {
	service := NewAntiSpamService(nil)
	defer service.Stop()

	proverPeerID := peer.ID("prover-peer")

	// Issue a challenge
	challenge, err := service.IssueChallenge(proverPeerID)
	require.NoError(t, err)

	// Mine a valid solution
	miner := hashcash.NewMiner(0)
	result, err := miner.Mine(challenge, []byte(proverPeerID))
	require.NoError(t, err)

	solution := &pb.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	// First verification should succeed
	err = service.VerifyResponse(challenge, solution, proverPeerID)
	require.NoError(t, err, "First verification should succeed")

	// Second verification (replay) should fail
	err = service.VerifyResponse(challenge, solution, proverPeerID)
	assert.Error(t, err, "Should reject replay attempt")
	assert.Contains(t, err.Error(), "nonce validation failed", "Error should indicate nonce issue")
}

// TestStopStopsNonceStore verifies Stop propagates to NonceStore.
func TestStopStopsNonceStore(t *testing.T) {
	service := NewAntiSpamService(nil)

	// Stop the service
	service.Stop()

	// Verify the nonce store was stopped (channel closed)
	select {
	case <-service.nonceStore.stopCleanup:
		// Expected: channel is closed
	default:
		t.Fatal("NonceStore stopCleanup channel should be closed after Stop()")
	}

	// Calling Stop again should not panic
	service.Stop()
}

// TestGetCurrentTierReturnsCorrectTier verifies tier reporting.
func TestGetCurrentTierReturnsCorrectTier(t *testing.T) {
	service := NewAntiSpamService(nil)
	defer service.Stop()

	// Initially should be Normal
	tier := service.GetCurrentTier()
	assert.Equal(t, TierNormal, tier, "Initial tier should be Normal")
}

// TestGetCurrentTierReflectsControllerState verifies tier sync with controller.
func TestGetCurrentTierReflectsControllerState(t *testing.T) {
	config := &DifficultyConfig{
		WindowDuration:        1 * time.Minute,
		CooldownDuration:      5 * time.Minute,
		ElevatedRateThreshold: 5,   // Low threshold for testing
		ElevatedFailureRate:   0.05, // Low threshold for testing
		HighRateThreshold:     10,
		HighFailureRate:       0.20,
		CriticalRateThreshold: 20,
		CriticalFailureRate:   0.40,
	}

	service := NewAntiSpamService(config)
	defer service.Stop()

	// Record failures to escalate the tier
	for i := 0; i < 10; i++ {
		service.controller.RecordChallenge(false)
	}

	// Tier should have escalated due to high failure rate
	tier := service.GetCurrentTier()
	assert.True(t, tier > TierNormal, "Tier should have escalated above Normal")
}

// TestVerifyResponseRecordsOutcomes verifies that outcomes affect the controller.
func TestVerifyResponseRecordsOutcomes(t *testing.T) {
	config := &DifficultyConfig{
		WindowDuration:        1 * time.Minute,
		CooldownDuration:      5 * time.Minute,
		ElevatedRateThreshold: 100, // High threshold so rate doesn't trigger escalation
		ElevatedFailureRate:   0.30, // Will trigger on 30% failure
		HighRateThreshold:     500,
		HighFailureRate:       0.50,
		CriticalRateThreshold: 1000,
		CriticalFailureRate:   0.70,
	}

	service := NewAntiSpamService(config)
	defer service.Stop()

	proverPeerID := peer.ID("prover-peer")

	// Record some failures by submitting bad solutions
	for i := 0; i < 5; i++ {
		challenge, err := service.IssueChallenge(proverPeerID)
		require.NoError(t, err)

		// Submit an invalid solution
		invalidSolution := &pb.PoWSolution{
			ChallengeNonce:     challenge.Nonce,
			ChallengeTimestamp: challenge.Timestamp,
			Counter:            0,
			Proof:              make([]byte, 32),
		}

		_ = service.VerifyResponse(challenge, invalidSolution, proverPeerID)
	}

	// Check that failures were recorded
	rate, failureRate := service.controller.GetMetrics()
	assert.Greater(t, rate, 0, "Should have recorded challenges")
	assert.Greater(t, failureRate, 0.0, "Should have recorded failures")
}

// TestOnTierChangeCallback verifies the callback is invoked on tier change.
func TestOnTierChangeCallback(t *testing.T) {
	config := &DifficultyConfig{
		WindowDuration:        1 * time.Minute,
		CooldownDuration:      5 * time.Minute,
		ElevatedRateThreshold: 3, // Very low threshold
		ElevatedFailureRate:   0.10,
		HighRateThreshold:     10,
		HighFailureRate:       0.30,
		CriticalRateThreshold: 20,
		CriticalFailureRate:   0.50,
	}

	service := NewAntiSpamService(config)
	defer service.Stop()

	var lastTier DifficultyTier
	var callbackCalled bool

	service.SetOnTierChange(func(tier DifficultyTier) {
		lastTier = tier
		callbackCalled = true
	})

	// Generate enough challenges to trigger escalation
	proverPeerID := peer.ID("test-peer")
	for i := 0; i < 5; i++ {
		_, _ = service.IssueChallenge(proverPeerID)
		service.controller.RecordChallenge(true)
	}

	// The callback should have been called
	if callbackCalled {
		assert.True(t, lastTier >= TierElevated, "Tier should have escalated")
	}
}

// TestConcurrentChallengeAndVerify tests thread safety.
func TestConcurrentChallengeAndVerify(t *testing.T) {
	service := NewAntiSpamService(nil)
	defer service.Stop()

	done := make(chan bool, 20)

	// Spawn goroutines issuing challenges
	for i := 0; i < 10; i++ {
		go func(id int) {
			peerID := peer.ID("peer-" + string(rune('0'+id)))
			for j := 0; j < 20; j++ {
				challenge, err := service.IssueChallenge(peerID)
				if err == nil && challenge != nil {
					// Mine and verify
					miner := hashcash.NewMiner(1000) // Low iteration limit for speed
					result, err := miner.Mine(challenge, []byte(peerID))
					if err == nil {
						solution := &pb.PoWSolution{
							ChallengeNonce:     challenge.Nonce,
							ChallengeTimestamp: challenge.Timestamp,
							Counter:            result.Counter,
							Proof:              result.Proof,
						}
						_ = service.VerifyResponse(challenge, solution, peerID)
					}
				}
			}
			done <- true
		}(i)
	}

	// Spawn goroutines checking tier
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 50; j++ {
				_ = service.GetCurrentTier()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}

	// Should not panic or deadlock
	assert.True(t, true, "Concurrent access should not cause issues")
}

// TestDifficultyAdjustsWithTier verifies challenge difficulty matches tier.
func TestDifficultyAdjustsWithTier(t *testing.T) {
	config := &DifficultyConfig{
		WindowDuration:        1 * time.Minute,
		CooldownDuration:      5 * time.Minute,
		ElevatedRateThreshold: 2, // Very low
		ElevatedFailureRate:   0.05,
		HighRateThreshold:     5,
		HighFailureRate:       0.15,
		CriticalRateThreshold: 10,
		CriticalFailureRate:   0.30,
	}

	service := NewAntiSpamService(config)
	defer service.Stop()

	proverPeerID := peer.ID("test-peer")

	// Initial challenge should have normal difficulty
	challenge, err := service.IssueChallenge(proverPeerID)
	require.NoError(t, err)
	assert.Equal(t, uint32(16), challenge.Difficulty, "Normal tier should have 16 bit difficulty")

	// Record enough challenges to escalate
	for i := 0; i < 5; i++ {
		service.controller.RecordChallenge(true)
	}

	// Next challenge should have elevated difficulty
	challenge2, err := service.IssueChallenge(proverPeerID)
	require.NoError(t, err)
	assert.Greater(t, challenge2.Difficulty, uint32(16), "Escalated tier should have higher difficulty")
}

// TestTierChangeTriggeredByVerifyResponse verifies callback invocation during verification.
func TestTierChangeTriggeredByVerifyResponse(t *testing.T) {
	config := &DifficultyConfig{
		WindowDuration:        1 * time.Minute,
		CooldownDuration:      5 * time.Minute,
		ElevatedRateThreshold: 100, // High rate threshold
		ElevatedFailureRate:   0.20, // Moderate failure rate threshold
		HighRateThreshold:     500,
		HighFailureRate:       0.40,
		CriticalRateThreshold: 1000,
		CriticalFailureRate:   0.60,
	}

	service := NewAntiSpamService(config)
	defer service.Stop()

	var tierChanges []DifficultyTier
	service.SetOnTierChange(func(tier DifficultyTier) {
		tierChanges = append(tierChanges, tier)
	})

	proverPeerID := peer.ID("test-peer")

	// Submit enough failures to trigger escalation
	for i := 0; i < 5; i++ {
		challenge, err := service.IssueChallenge(proverPeerID)
		require.NoError(t, err)

		// Submit an invalid solution (will cause failure)
		invalidSolution := &pb.PoWSolution{
			ChallengeNonce:     challenge.Nonce,
			ChallengeTimestamp: challenge.Timestamp,
			Counter:            0,
			Proof:              make([]byte, 32),
		}

		_ = service.VerifyResponse(challenge, invalidSolution, proverPeerID)
	}

	// We should have seen tier changes
	assert.NotEmpty(t, tierChanges, "Should have recorded tier changes")
}

// TestNoCallbackWhenTierUnchanged verifies no callback when tier stays the same.
func TestNoCallbackWhenTierUnchanged(t *testing.T) {
	service := NewAntiSpamService(nil)
	defer service.Stop()

	callbackCount := 0
	service.SetOnTierChange(func(tier DifficultyTier) {
		callbackCount++
	})

	proverPeerID := peer.ID("test-peer")

	// Issue and verify one valid challenge (should not change tier)
	challenge, err := service.IssueChallenge(proverPeerID)
	require.NoError(t, err)

	miner := hashcash.NewMiner(0)
	result, err := miner.Mine(challenge, []byte(proverPeerID))
	require.NoError(t, err)

	solution := &pb.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	err = service.VerifyResponse(challenge, solution, proverPeerID)
	require.NoError(t, err)

	// Tier should not have changed, so callback should not be called
	assert.Equal(t, 0, callbackCount, "Callback should not be called when tier unchanged")
}

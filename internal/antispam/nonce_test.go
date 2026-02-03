// Package antispam provides load-adaptive spam prevention for the MyMonad P2P protocol.
package antispam

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewNonceStore verifies that a new nonce store is created correctly.
func TestNewNonceStore(t *testing.T) {
	store := NewNonceStore()
	require.NotNil(t, store, "NewNonceStore should return a non-nil store")

	// Verify initial state
	total, pending, used := store.Stats()
	assert.Equal(t, 0, total, "New store should have zero total nonces")
	assert.Equal(t, 0, pending, "New store should have zero pending nonces")
	assert.Equal(t, 0, used, "New store should have zero used nonces")

	// Clean up
	store.Stop()
}

// TestNewNonceStoreStartsCleanupLoop verifies that the cleanup goroutine starts.
func TestNewNonceStoreStartsCleanupLoop(t *testing.T) {
	store := NewNonceStore()
	require.NotNil(t, store)

	// The store should have a stopCleanup channel that's not closed
	// This verifies the cleanup loop is running
	select {
	case <-store.stopCleanup:
		t.Fatal("stopCleanup channel should not be closed on new store")
	default:
		// Expected: channel is open, cleanup loop is running
	}

	store.Stop()
}

// TestGenerateChallengeProducesUniqueNonces verifies that generated nonces are unique.
func TestGenerateChallengeProducesUniqueNonces(t *testing.T) {
	store := NewNonceStore()
	defer store.Stop()

	peerID := peer.ID("test-peer")
	difficulty := uint32(16)
	expiration := 30 * time.Second

	// Generate multiple challenges and verify uniqueness
	nonces := make(map[string]bool)
	for i := 0; i < 100; i++ {
		challenge, err := store.GenerateChallenge(peerID, difficulty, expiration)
		require.NoError(t, err, "GenerateChallenge should not return an error")
		require.NotNil(t, challenge, "Challenge should not be nil")

		nonceHex := string(challenge.Nonce)
		assert.False(t, nonces[nonceHex], "Nonce should be unique")
		nonces[nonceHex] = true

		// Verify nonce length
		assert.Len(t, challenge.Nonce, NonceLength, "Nonce should be %d bytes", NonceLength)

		// Verify challenge fields
		assert.Equal(t, difficulty, challenge.Difficulty, "Difficulty should match")
		assert.NotZero(t, challenge.Timestamp, "Timestamp should be set")
	}
}

// TestGenerateChallengeBindsToPeer verifies that challenges are bound to peers.
func TestGenerateChallengeBindsToPeer(t *testing.T) {
	store := NewNonceStore()
	defer store.Stop()

	peerID := peer.ID("test-peer")
	challenge, err := store.GenerateChallenge(peerID, 16, 30*time.Second)
	require.NoError(t, err)
	require.NotNil(t, challenge)

	// The peer ID should be stored in the challenge
	assert.Equal(t, []byte(peerID), challenge.PeerId, "Challenge should contain peer ID")
}

// TestGenerateChallengeEnforcesCapacity verifies capacity limits.
func TestGenerateChallengeEnforcesCapacity(t *testing.T) {
	store := NewNonceStore()
	defer store.Stop()

	peerID := peer.ID("test-peer")

	// Fill the store to capacity
	for i := 0; i < MaxPendingNonces; i++ {
		_, err := store.GenerateChallenge(peerID, 16, 1*time.Hour)
		require.NoError(t, err, "Should be able to generate challenge up to capacity")
	}

	// Verify we're at capacity
	total, _, _ := store.Stats()
	assert.Equal(t, MaxPendingNonces, total, "Should be at capacity")

	// Next generation should fail
	_, err := store.GenerateChallenge(peerID, 16, 1*time.Hour)
	assert.Error(t, err, "Should fail when at capacity")
	assert.Contains(t, err.Error(), "nonce store at capacity", "Error should indicate capacity issue")
}

// TestValidateAndConsumeSucceedsForValidNonce verifies successful validation.
func TestValidateAndConsumeSucceedsForValidNonce(t *testing.T) {
	store := NewNonceStore()
	defer store.Stop()

	peerID := peer.ID("test-peer")
	challenge, err := store.GenerateChallenge(peerID, 16, 30*time.Second)
	require.NoError(t, err)

	// Validate the nonce
	record, err := store.ValidateAndConsume(challenge.Nonce, peerID)
	require.NoError(t, err, "ValidateAndConsume should succeed for valid nonce")
	require.NotNil(t, record, "Record should not be nil")

	// Verify record fields
	assert.Equal(t, challenge.Nonce, record.nonce, "Record nonce should match")
	assert.Equal(t, uint32(16), record.difficulty, "Record difficulty should match")
	assert.Equal(t, peerID, record.peerID, "Record peer ID should match")
	assert.True(t, record.used, "Record should be marked as used")
}

// TestValidateAndConsumeRejectsUnknownNonce verifies unknown nonce rejection.
func TestValidateAndConsumeRejectsUnknownNonce(t *testing.T) {
	store := NewNonceStore()
	defer store.Stop()

	peerID := peer.ID("test-peer")
	unknownNonce := make([]byte, NonceLength)
	copy(unknownNonce, "unknown-nonce-12")

	record, err := store.ValidateAndConsume(unknownNonce, peerID)
	assert.Error(t, err, "Should reject unknown nonce")
	assert.Nil(t, record, "Record should be nil for unknown nonce")
	assert.Contains(t, err.Error(), "unknown nonce", "Error should indicate unknown nonce")
}

// TestValidateAndConsumeRejectsWrongPeer verifies peer binding enforcement.
func TestValidateAndConsumeRejectsWrongPeer(t *testing.T) {
	store := NewNonceStore()
	defer store.Stop()

	originalPeer := peer.ID("original-peer")
	wrongPeer := peer.ID("wrong-peer")

	challenge, err := store.GenerateChallenge(originalPeer, 16, 30*time.Second)
	require.NoError(t, err)

	// Try to validate with wrong peer
	record, err := store.ValidateAndConsume(challenge.Nonce, wrongPeer)
	assert.Error(t, err, "Should reject nonce from wrong peer")
	assert.Nil(t, record, "Record should be nil for wrong peer")
	assert.Contains(t, err.Error(), "nonce bound to different peer", "Error should indicate peer mismatch")
}

// TestValidateAndConsumeRejectsExpiredNonce verifies expiration enforcement.
func TestValidateAndConsumeRejectsExpiredNonce(t *testing.T) {
	store := NewNonceStore()
	defer store.Stop()

	peerID := peer.ID("test-peer")

	// Generate a challenge with very short expiration
	challenge, err := store.GenerateChallenge(peerID, 16, 1*time.Millisecond)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Try to validate expired nonce
	record, err := store.ValidateAndConsume(challenge.Nonce, peerID)
	assert.Error(t, err, "Should reject expired nonce")
	assert.Nil(t, record, "Record should be nil for expired nonce")
	assert.Contains(t, err.Error(), "nonce expired", "Error should indicate expiration")
}

// TestValidateAndConsumeRejectsReplayAttack verifies replay prevention.
func TestValidateAndConsumeRejectsReplayAttack(t *testing.T) {
	store := NewNonceStore()
	defer store.Stop()

	peerID := peer.ID("test-peer")
	challenge, err := store.GenerateChallenge(peerID, 16, 30*time.Second)
	require.NoError(t, err)

	// First validation should succeed
	_, err = store.ValidateAndConsume(challenge.Nonce, peerID)
	require.NoError(t, err, "First validation should succeed")

	// Second validation (replay) should fail
	record, err := store.ValidateAndConsume(challenge.Nonce, peerID)
	assert.Error(t, err, "Should reject replay attempt")
	assert.Nil(t, record, "Record should be nil for replay")
	assert.Contains(t, err.Error(), "nonce already used", "Error should indicate replay")
}

// TestCleanupLoopEvictsExpiredNonces verifies cleanup of expired nonces.
func TestCleanupLoopEvictsExpiredNonces(t *testing.T) {
	store := NewNonceStoreWithCleanupInterval(50 * time.Millisecond)
	defer store.Stop()

	peerID := peer.ID("test-peer")

	// Generate a challenge with short expiration
	_, err := store.GenerateChallenge(peerID, 16, 10*time.Millisecond)
	require.NoError(t, err)

	// Verify it's in the store
	total, _, _ := store.Stats()
	assert.Equal(t, 1, total, "Should have one nonce")

	// Wait for expiration and cleanup
	time.Sleep(100 * time.Millisecond)

	// Verify it was cleaned up
	total, _, _ = store.Stats()
	assert.Equal(t, 0, total, "Expired nonce should be evicted by cleanup loop")
}

// TestCleanupLoopEvictsUsedNonces verifies cleanup of used nonces.
func TestCleanupLoopEvictsUsedNonces(t *testing.T) {
	store := NewNonceStoreWithCleanupInterval(50 * time.Millisecond)
	defer store.Stop()

	peerID := peer.ID("test-peer")

	// Generate and consume a challenge
	challenge, err := store.GenerateChallenge(peerID, 16, 1*time.Hour)
	require.NoError(t, err)

	_, err = store.ValidateAndConsume(challenge.Nonce, peerID)
	require.NoError(t, err)

	// Verify it's marked as used
	_, _, used := store.Stats()
	assert.Equal(t, 1, used, "Should have one used nonce")

	// Wait for cleanup
	time.Sleep(100 * time.Millisecond)

	// Verify used nonce was cleaned up
	total, _, _ := store.Stats()
	assert.Equal(t, 0, total, "Used nonce should be evicted by cleanup loop")
}

// TestStopStopsCleanupLoop verifies that Stop() stops the cleanup goroutine.
func TestStopStopsCleanupLoop(t *testing.T) {
	store := NewNonceStore()

	// Stop the store
	store.Stop()

	// Verify the channel is closed
	select {
	case <-store.stopCleanup:
		// Expected: channel is closed
	default:
		t.Fatal("stopCleanup channel should be closed after Stop()")
	}

	// Calling Stop again should not panic
	store.Stop()
}

// TestStatsReturnsCorrectCounts verifies statistics are accurate.
func TestStatsReturnsCorrectCounts(t *testing.T) {
	store := NewNonceStore()
	defer store.Stop()

	peerID := peer.ID("test-peer")

	// Generate some challenges
	for i := 0; i < 5; i++ {
		_, err := store.GenerateChallenge(peerID, 16, 1*time.Hour)
		require.NoError(t, err)
	}

	total, pending, used := store.Stats()
	assert.Equal(t, 5, total, "Total should be 5")
	assert.Equal(t, 5, pending, "Pending should be 5")
	assert.Equal(t, 0, used, "Used should be 0")

	// Consume some nonces
	store.mu.RLock()
	var noncesToConsume [][]byte
	count := 0
	for _, record := range store.nonces {
		if count < 2 {
			noncesToConsume = append(noncesToConsume, record.nonce)
			count++
		}
	}
	store.mu.RUnlock()

	for _, nonce := range noncesToConsume {
		_, err := store.ValidateAndConsume(nonce, peerID)
		require.NoError(t, err)
	}

	total, pending, used = store.Stats()
	assert.Equal(t, 5, total, "Total should still be 5")
	assert.Equal(t, 3, pending, "Pending should be 3")
	assert.Equal(t, 2, used, "Used should be 2")
}

// TestNonceStoreConcurrentAccess verifies thread safety of the nonce store.
func TestNonceStoreConcurrentAccess(t *testing.T) {
	store := NewNonceStore()
	defer store.Stop()

	done := make(chan bool, 20)

	// Spawn goroutines generating challenges
	for i := 0; i < 10; i++ {
		go func(id int) {
			peerID := peer.ID("peer-" + string(rune('0'+id)))
			for j := 0; j < 50; j++ {
				_, _ = store.GenerateChallenge(peerID, 16, 1*time.Hour)
			}
			done <- true
		}(i)
	}

	// Spawn goroutines reading stats
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				store.Stats()
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

// TestValidateAndConsumeWithNilNonce verifies nil nonce handling.
func TestValidateAndConsumeWithNilNonce(t *testing.T) {
	store := NewNonceStore()
	defer store.Stop()

	peerID := peer.ID("test-peer")
	record, err := store.ValidateAndConsume(nil, peerID)

	assert.Error(t, err, "Should reject nil nonce")
	assert.Nil(t, record, "Record should be nil")
	assert.Contains(t, err.Error(), "unknown nonce", "Error should indicate unknown nonce")
}

// TestValidateAndConsumeWithEmptyNonce verifies empty nonce handling.
func TestValidateAndConsumeWithEmptyNonce(t *testing.T) {
	store := NewNonceStore()
	defer store.Stop()

	peerID := peer.ID("test-peer")
	record, err := store.ValidateAndConsume([]byte{}, peerID)

	assert.Error(t, err, "Should reject empty nonce")
	assert.Nil(t, record, "Record should be nil")
	assert.Contains(t, err.Error(), "unknown nonce", "Error should indicate unknown nonce")
}

// TestGenerateChallengeWithZeroExpiration verifies zero expiration handling.
func TestGenerateChallengeWithZeroExpiration(t *testing.T) {
	store := NewNonceStore()
	defer store.Stop()

	peerID := peer.ID("test-peer")

	// Generate challenge with zero expiration (should immediately expire)
	challenge, err := store.GenerateChallenge(peerID, 16, 0)
	require.NoError(t, err, "Should generate challenge with zero expiration")

	// Trying to validate should fail immediately due to expiration
	_, err = store.ValidateAndConsume(challenge.Nonce, peerID)
	assert.Error(t, err, "Should reject immediately expired nonce")
	assert.Contains(t, err.Error(), "nonce expired", "Error should indicate expiration")
}

// TestNonceRecordFields verifies all record fields are set correctly.
func TestNonceRecordFields(t *testing.T) {
	store := NewNonceStore()
	defer store.Stop()

	peerID := peer.ID("test-peer")
	difficulty := uint32(20)
	expiration := 45 * time.Second

	beforeCreate := time.Now()
	challenge, err := store.GenerateChallenge(peerID, difficulty, expiration)
	require.NoError(t, err)
	afterCreate := time.Now()

	// Get the record by validating
	record, err := store.ValidateAndConsume(challenge.Nonce, peerID)
	require.NoError(t, err)

	// Verify all fields
	assert.Equal(t, challenge.Nonce, record.nonce, "Nonce should match")
	assert.Equal(t, difficulty, record.difficulty, "Difficulty should match")
	assert.Equal(t, peerID, record.peerID, "PeerID should match")
	assert.True(t, record.used, "Should be marked as used after validation")

	// Verify timestamps are reasonable
	assert.True(t, record.createdAt.After(beforeCreate) || record.createdAt.Equal(beforeCreate),
		"CreatedAt should be >= beforeCreate")
	assert.True(t, record.createdAt.Before(afterCreate) || record.createdAt.Equal(afterCreate),
		"CreatedAt should be <= afterCreate")
	assert.True(t, record.expiresAt.After(record.createdAt),
		"ExpiresAt should be after createdAt")
}

// Package antispam provides load-adaptive spam prevention for the MyMonad P2P protocol.
//
// AntiSpamService integrates the DifficultyController and NonceStore to provide
// a complete challenge-response workflow for proof-of-work based spam prevention.
//
// # Usage
//
// The service is used during the handshake process:
//
//  1. When a peer connects, call IssueChallenge to generate a PoW challenge
//  2. Send the challenge to the connecting peer
//  3. When the peer responds with a solution, call VerifyResponse to validate it
//  4. If verification succeeds, proceed with the handshake; otherwise reject
//
// # Thread Safety
//
// AntiSpamService is safe for concurrent use from multiple goroutines.
package antispam

import (
	"fmt"
	"sync"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
	"github.com/mymonad/mymonad/pkg/hashcash"

	"github.com/libp2p/go-libp2p/core/peer"
)

// AntiSpamService integrates the DifficultyController and NonceStore to provide
// a complete challenge-response proof-of-work system for spam prevention.
type AntiSpamService struct {
	controller *DifficultyController
	nonceStore *NonceStore

	// callbackMu protects onTierChange from concurrent access.
	callbackMu sync.RWMutex
	// onTierChange is an optional callback invoked when the difficulty tier changes.
	// This can be used for metrics export or logging.
	onTierChange func(tier DifficultyTier)
}

// NewAntiSpamService creates a new AntiSpamService with the given configuration.
// If config is nil, default configuration is used.
func NewAntiSpamService(config *DifficultyConfig) *AntiSpamService {
	return &AntiSpamService{
		controller: NewDifficultyController(config),
		nonceStore: NewNonceStore(),
	}
}

// IssueChallenge creates a challenge for an incoming handshake request.
// The challenge difficulty is determined by the current load conditions.
//
// The returned challenge should be sent to the connecting peer, who must
// solve it and return a PoWSolution.
func (as *AntiSpamService) IssueChallenge(peerID peer.ID) (*pb.PoWChallenge, error) {
	bits, expiration := as.controller.GetCurrentDifficulty()
	return as.nonceStore.GenerateChallenge(peerID, bits, expiration)
}

// VerifyResponse validates a PoW solution and records the outcome.
//
// The verification process:
//  1. Validates that the nonce exists and is bound to the prover peer
//  2. Checks that the challenge has not expired
//  3. Verifies the proof meets the required difficulty
//
// On success, the challenge is consumed and cannot be reused (replay prevention).
// Both success and failure outcomes are recorded to adjust future difficulty.
func (as *AntiSpamService) VerifyResponse(
	challenge *pb.PoWChallenge,
	solution *pb.PoWSolution,
	proverPeerID peer.ID,
) error {
	// Track the previous tier for change detection
	previousTier := as.controller.GetCurrentTier()

	// Validate nonce exists and is fresh (also marks it as consumed)
	record, err := as.nonceStore.ValidateAndConsume(challenge.Nonce, proverPeerID)
	if err != nil {
		as.controller.RecordChallenge(false)
		as.checkTierChange(previousTier)
		return fmt.Errorf("nonce validation failed: %w", err)
	}

	// Check timestamp within the challenge window
	// The record's validity window is determined by expiration duration
	challengeTime := time.UnixMilli(challenge.Timestamp)
	validityDuration := record.expiresAt.Sub(record.createdAt)
	if time.Since(challengeTime) > validityDuration {
		as.controller.RecordChallenge(false)
		as.checkTierChange(previousTier)
		return fmt.Errorf("challenge expired")
	}

	// Verify the proof
	if err := hashcash.Verify(challenge, solution, []byte(proverPeerID)); err != nil {
		as.controller.RecordChallenge(false)
		as.checkTierChange(previousTier)
		return fmt.Errorf("proof verification failed: %w", err)
	}

	// Success
	as.controller.RecordChallenge(true)
	as.checkTierChange(previousTier)
	return nil
}

// Stop stops the AntiSpamService and releases resources.
// It stops the NonceStore's cleanup goroutine.
// It is safe to call Stop multiple times.
func (as *AntiSpamService) Stop() {
	as.nonceStore.Stop()
}

// GetCurrentTier returns the current difficulty tier.
// This reflects the load-adaptive state of the system.
func (as *AntiSpamService) GetCurrentTier() DifficultyTier {
	return as.controller.GetCurrentTier()
}

// SetOnTierChange sets a callback that is invoked when the difficulty tier changes.
// This can be used for metrics export or logging.
// Pass nil to remove the callback.
func (as *AntiSpamService) SetOnTierChange(callback func(tier DifficultyTier)) {
	as.callbackMu.Lock()
	defer as.callbackMu.Unlock()
	as.onTierChange = callback
}

// checkTierChange invokes the tier change callback if the tier has changed.
func (as *AntiSpamService) checkTierChange(previousTier DifficultyTier) {
	currentTier := as.controller.GetCurrentTier()
	if currentTier != previousTier {
		// Read callback under lock, call outside lock (avoids blocking if callback is slow)
		as.callbackMu.RLock()
		cb := as.onTierChange
		as.callbackMu.RUnlock()
		if cb != nil {
			cb(currentTier)
		}
	}
}

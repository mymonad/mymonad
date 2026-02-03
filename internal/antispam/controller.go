// Package antispam provides load-adaptive spam prevention for the MyMonad P2P protocol.
//
// The difficulty controller dynamically adjusts proof-of-work requirements based on
// request rate and failure ratio. It uses a sliding window to track recent challenge
// outcomes and escalates difficulty when thresholds are exceeded.
//
// # Difficulty Tiers
//
// The controller defines four difficulty tiers, each with increasing PoW requirements:
//   - TierNormal (16 bits): Normal operation, minimal computational cost
//   - TierElevated (20 bits): Elevated load, moderate computational cost
//   - TierHigh (24 bits): High load, significant computational cost
//   - TierCritical (28 bits): Critical load, maximum computational cost
//
// # Escalation
//
// Difficulty escalates immediately when either:
//   - Request rate exceeds tier threshold
//   - Failure rate exceeds tier threshold
//
// # De-escalation
//
// Difficulty de-escalates one tier at a time after a cooldown period has passed
// and metrics fall below the lower tier's thresholds.
package antispam

import (
	"sync"
	"time"
)

// DifficultyTier represents a difficulty level for PoW challenges.
type DifficultyTier uint8

// Difficulty tiers from lowest to highest.
const (
	// TierNormal is the default tier with 16 bits difficulty.
	TierNormal DifficultyTier = iota

	// TierElevated has 20 bits difficulty, triggered by moderate load.
	TierElevated

	// TierHigh has 24 bits difficulty, triggered by high load.
	TierHigh

	// TierCritical has 28 bits difficulty, triggered by critical load.
	TierCritical
)

// Bits returns the number of leading zero bits required for this tier's PoW.
func (t DifficultyTier) Bits() uint32 {
	bits := []uint32{16, 20, 24, 28}
	if int(t) >= len(bits) {
		return bits[len(bits)-1]
	}
	return bits[t]
}

// Expiration returns the challenge expiration duration for this tier.
// Higher tiers have longer expirations to give clients time to solve harder challenges.
func (t DifficultyTier) Expiration() time.Duration {
	expirations := []time.Duration{
		30 * time.Second,
		60 * time.Second,
		90 * time.Second,
		120 * time.Second,
	}
	if int(t) >= len(expirations) {
		return expirations[len(expirations)-1]
	}
	return expirations[t]
}

// String returns the human-readable name of the tier.
func (t DifficultyTier) String() string {
	names := []string{"Normal", "Elevated", "High", "Critical"}
	if int(t) >= len(names) {
		return "Unknown"
	}
	return names[t]
}

// DifficultyConfig holds the configuration for the difficulty controller.
type DifficultyConfig struct {
	// WindowDuration is the sliding window duration for tracking challenges.
	// Only challenges within this window are considered for metrics.
	WindowDuration time.Duration

	// CooldownDuration is the minimum time that must pass before de-escalation.
	CooldownDuration time.Duration

	// ElevatedRateThreshold is the request rate (per window) that triggers TierElevated.
	ElevatedRateThreshold int

	// ElevatedFailureRate is the failure rate that triggers TierElevated.
	ElevatedFailureRate float64

	// HighRateThreshold is the request rate that triggers TierHigh.
	HighRateThreshold int

	// HighFailureRate is the failure rate that triggers TierHigh.
	HighFailureRate float64

	// CriticalRateThreshold is the request rate that triggers TierCritical.
	CriticalRateThreshold int

	// CriticalFailureRate is the failure rate that triggers TierCritical.
	CriticalFailureRate float64
}

// DefaultDifficultyConfig returns a DifficultyConfig with sensible defaults.
func DefaultDifficultyConfig() *DifficultyConfig {
	return &DifficultyConfig{
		WindowDuration:   1 * time.Minute,
		CooldownDuration: 5 * time.Minute,

		ElevatedRateThreshold: 10,
		ElevatedFailureRate:   0.10,

		HighRateThreshold: 50,
		HighFailureRate:   0.30,

		CriticalRateThreshold: 100,
		CriticalFailureRate:   0.50,
	}
}

// challengeRecord represents a single challenge outcome in the sliding window.
type challengeRecord struct {
	timestamp time.Time
	succeeded bool
}

// DifficultyController manages adaptive PoW difficulty based on load metrics.
// It tracks challenge outcomes in a sliding window and adjusts difficulty tier
// based on request rate and failure rate.
//
// The controller is safe for concurrent use.
type DifficultyController struct {
	mu sync.RWMutex

	currentTier   DifficultyTier
	tierEnteredAt time.Time

	// Sliding window metrics
	windowDuration time.Duration
	challenges     []challengeRecord

	// Configuration
	config *DifficultyConfig
}

// NewDifficultyController creates a new DifficultyController with the given configuration.
// If config is nil, default configuration is used.
func NewDifficultyController(config *DifficultyConfig) *DifficultyController {
	if config == nil {
		config = DefaultDifficultyConfig()
	}

	return &DifficultyController{
		currentTier:    TierNormal,
		tierEnteredAt:  time.Now(),
		windowDuration: config.WindowDuration,
		challenges:     make([]challengeRecord, 0),
		config:         config,
	}
}

// RecordChallenge records a challenge outcome and recalculates the difficulty tier.
// Pass true for succeeded if the challenge was successfully verified, false otherwise.
func (dc *DifficultyController) RecordChallenge(succeeded bool) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	now := time.Now()

	// Add the new record
	dc.challenges = append(dc.challenges, challengeRecord{
		timestamp: now,
		succeeded: succeeded,
	})

	// Evict stale records
	dc.evictStale(now)

	// Recalculate tier
	dc.recalculateTier(now)
}

// GetCurrentDifficulty returns the current PoW difficulty (bits) and challenge expiration.
func (dc *DifficultyController) GetCurrentDifficulty() (bits uint32, expiration time.Duration) {
	dc.mu.RLock()
	defer dc.mu.RUnlock()

	return dc.currentTier.Bits(), dc.currentTier.Expiration()
}

// GetCurrentTier returns the current difficulty tier.
func (dc *DifficultyController) GetCurrentTier() DifficultyTier {
	dc.mu.RLock()
	defer dc.mu.RUnlock()

	return dc.currentTier
}

// GetMetrics returns the current request rate (count in window) and failure rate.
// This is useful for monitoring and debugging.
func (dc *DifficultyController) GetMetrics() (rate int, failureRate float64) {
	dc.mu.RLock()
	defer dc.mu.RUnlock()

	// Evict stale records first (need write lock for this)
	dc.mu.RUnlock()
	dc.mu.Lock()
	dc.evictStale(time.Now())
	dc.mu.Unlock()
	dc.mu.RLock()

	return dc.getMetricsLocked()
}

// getMetricsLocked calculates metrics assuming the lock is already held.
func (dc *DifficultyController) getMetricsLocked() (rate int, failureRate float64) {
	total := len(dc.challenges)
	if total == 0 {
		return 0, 0.0
	}

	failures := 0
	for _, record := range dc.challenges {
		if !record.succeeded {
			failures++
		}
	}

	return total, float64(failures) / float64(total)
}

// evictStale removes challenge records outside the sliding window.
// Must be called with the lock held.
func (dc *DifficultyController) evictStale(now time.Time) {
	cutoff := now.Add(-dc.windowDuration)

	// Find the first non-stale record
	firstValid := 0
	for i, record := range dc.challenges {
		if record.timestamp.After(cutoff) {
			firstValid = i
			break
		}
		// If we've checked all and none are valid
		if i == len(dc.challenges)-1 {
			firstValid = len(dc.challenges)
		}
	}

	// Evict stale records
	if firstValid > 0 {
		dc.challenges = dc.challenges[firstValid:]
	}
}

// recalculateTier determines the appropriate tier based on current metrics.
// Must be called with the lock held.
func (dc *DifficultyController) recalculateTier(now time.Time) {
	rate, failureRate := dc.getMetricsLocked()

	// Determine the appropriate tier based on metrics
	targetTier := dc.calculateTargetTier(rate, failureRate)

	// Handle escalation (immediate)
	if targetTier > dc.currentTier {
		dc.currentTier = targetTier
		dc.tierEnteredAt = now
		return
	}

	// Handle de-escalation (requires cooldown, one tier at a time)
	if targetTier < dc.currentTier {
		// Check if cooldown has passed
		if now.Sub(dc.tierEnteredAt) >= dc.config.CooldownDuration {
			// De-escalate one tier at a time
			dc.currentTier--
			dc.tierEnteredAt = now
		}
	}
}

// calculateTargetTier determines what tier the current metrics warrant.
func (dc *DifficultyController) calculateTargetTier(rate int, failureRate float64) DifficultyTier {
	// Check Critical thresholds
	if rate > dc.config.CriticalRateThreshold || failureRate > dc.config.CriticalFailureRate {
		return TierCritical
	}

	// Check High thresholds
	if rate > dc.config.HighRateThreshold || failureRate > dc.config.HighFailureRate {
		return TierHigh
	}

	// Check Elevated thresholds
	if rate > dc.config.ElevatedRateThreshold || failureRate > dc.config.ElevatedFailureRate {
		return TierElevated
	}

	return TierNormal
}

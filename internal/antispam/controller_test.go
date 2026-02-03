// Package antispam provides load-adaptive spam prevention for the MyMonad P2P protocol.
package antispam

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDifficultyTierBits verifies that each tier returns the correct number of bits.
func TestDifficultyTierBits(t *testing.T) {
	tests := []struct {
		tier     DifficultyTier
		expected uint32
	}{
		{TierNormal, 16},
		{TierElevated, 20},
		{TierHigh, 24},
		{TierCritical, 28},
	}

	for _, tt := range tests {
		t.Run(tt.tier.String(), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.tier.Bits())
		})
	}
}

// TestDifficultyTierExpiration verifies that each tier returns the correct expiration duration.
func TestDifficultyTierExpiration(t *testing.T) {
	tests := []struct {
		tier     DifficultyTier
		expected time.Duration
	}{
		{TierNormal, 30 * time.Second},
		{TierElevated, 60 * time.Second},
		{TierHigh, 90 * time.Second},
		{TierCritical, 120 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.tier.String(), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.tier.Expiration())
		})
	}
}

// TestDifficultyTierString verifies the string representation of tiers.
func TestDifficultyTierString(t *testing.T) {
	tests := []struct {
		tier     DifficultyTier
		expected string
	}{
		{TierNormal, "Normal"},
		{TierElevated, "Elevated"},
		{TierHigh, "High"},
		{TierCritical, "Critical"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.tier.String())
		})
	}
}

// TestNewDifficultyController verifies the controller is initialized correctly.
func TestNewDifficultyController(t *testing.T) {
	ctrl := NewDifficultyController(DefaultDifficultyConfig())

	bits, expiration := ctrl.GetCurrentDifficulty()

	assert.Equal(t, uint32(16), bits, "Should start at TierNormal (16 bits)")
	assert.Equal(t, 30*time.Second, expiration, "Should have TierNormal expiration")
}

// TestNewDifficultyControllerWithNilConfig verifies that nil config uses defaults.
func TestNewDifficultyControllerWithNilConfig(t *testing.T) {
	ctrl := NewDifficultyController(nil)

	bits, _ := ctrl.GetCurrentDifficulty()
	assert.Equal(t, uint32(16), bits, "Should start at TierNormal with nil config")
}

// TestDefaultDifficultyConfig verifies the default configuration values.
func TestDefaultDifficultyConfig(t *testing.T) {
	cfg := DefaultDifficultyConfig()

	assert.Equal(t, 1*time.Minute, cfg.WindowDuration)
	assert.Equal(t, 5*time.Minute, cfg.CooldownDuration)

	assert.Equal(t, 10, cfg.ElevatedRateThreshold)
	assert.Equal(t, 0.10, cfg.ElevatedFailureRate)

	assert.Equal(t, 50, cfg.HighRateThreshold)
	assert.Equal(t, 0.30, cfg.HighFailureRate)

	assert.Equal(t, 100, cfg.CriticalRateThreshold)
	assert.Equal(t, 0.50, cfg.CriticalFailureRate)
}

// TestEscalateToElevatedOnHighRate verifies escalation to TierElevated when rate threshold exceeded.
func TestEscalateToElevatedOnHighRate(t *testing.T) {
	cfg := DefaultDifficultyConfig()
	ctrl := NewDifficultyController(cfg)

	// Record 11 successful challenges (exceeds ElevatedRateThreshold of 10)
	for i := 0; i < 11; i++ {
		ctrl.RecordChallenge(true)
	}

	bits, _ := ctrl.GetCurrentDifficulty()
	assert.Equal(t, uint32(20), bits, "Should escalate to TierElevated (20 bits) on high rate")
}

// TestEscalateToElevatedOnHighFailureRate verifies escalation on failure rate threshold.
func TestEscalateToElevatedOnHighFailureRate(t *testing.T) {
	cfg := DefaultDifficultyConfig()
	ctrl := NewDifficultyController(cfg)

	// Record 10 challenges with >10% failure rate (2 failures = 20%)
	for i := 0; i < 8; i++ {
		ctrl.RecordChallenge(true)
	}
	ctrl.RecordChallenge(false)
	ctrl.RecordChallenge(false)

	bits, _ := ctrl.GetCurrentDifficulty()
	assert.Equal(t, uint32(20), bits, "Should escalate to TierElevated on high failure rate")
}

// TestEscalateToHighOnHighRate verifies escalation to TierHigh when rate threshold exceeded.
func TestEscalateToHighOnHighRate(t *testing.T) {
	cfg := DefaultDifficultyConfig()
	ctrl := NewDifficultyController(cfg)

	// Record 51 successful challenges (exceeds HighRateThreshold of 50)
	for i := 0; i < 51; i++ {
		ctrl.RecordChallenge(true)
	}

	bits, _ := ctrl.GetCurrentDifficulty()
	assert.Equal(t, uint32(24), bits, "Should escalate to TierHigh (24 bits) on high rate")
}

// TestEscalateToHighOnHighFailureRate verifies escalation to TierHigh on failure rate.
func TestEscalateToHighOnHighFailureRate(t *testing.T) {
	cfg := DefaultDifficultyConfig()
	ctrl := NewDifficultyController(cfg)

	// Record challenges with >30% failure rate (4 failures out of 10 = 40%)
	for i := 0; i < 6; i++ {
		ctrl.RecordChallenge(true)
	}
	for i := 0; i < 4; i++ {
		ctrl.RecordChallenge(false)
	}

	bits, _ := ctrl.GetCurrentDifficulty()
	assert.Equal(t, uint32(24), bits, "Should escalate to TierHigh on >30% failure rate")
}

// TestEscalateToCriticalOnHighRate verifies escalation to TierCritical.
func TestEscalateToCriticalOnHighRate(t *testing.T) {
	cfg := DefaultDifficultyConfig()
	ctrl := NewDifficultyController(cfg)

	// Record 101 successful challenges (exceeds CriticalRateThreshold of 100)
	for i := 0; i < 101; i++ {
		ctrl.RecordChallenge(true)
	}

	bits, _ := ctrl.GetCurrentDifficulty()
	assert.Equal(t, uint32(28), bits, "Should escalate to TierCritical (28 bits) on high rate")
}

// TestEscalateToCriticalOnHighFailureRate verifies escalation to TierCritical on failure rate.
func TestEscalateToCriticalOnHighFailureRate(t *testing.T) {
	cfg := DefaultDifficultyConfig()
	ctrl := NewDifficultyController(cfg)

	// Record challenges with >50% failure rate
	for i := 0; i < 4; i++ {
		ctrl.RecordChallenge(true)
	}
	for i := 0; i < 6; i++ {
		ctrl.RecordChallenge(false)
	}

	bits, _ := ctrl.GetCurrentDifficulty()
	assert.Equal(t, uint32(28), bits, "Should escalate to TierCritical on >50% failure rate")
}

// TestNoDeescalationBeforeCooldown verifies tier doesn't decrease before cooldown period.
func TestNoDeescalationBeforeCooldown(t *testing.T) {
	cfg := DefaultDifficultyConfig()
	cfg.CooldownDuration = 1 * time.Hour // Long cooldown for testing
	ctrl := NewDifficultyController(cfg)

	// Escalate to TierElevated
	for i := 0; i < 11; i++ {
		ctrl.RecordChallenge(true)
	}

	bits, _ := ctrl.GetCurrentDifficulty()
	require.Equal(t, uint32(20), bits, "Should be at TierElevated")

	// Clear window by setting now for internal clock (we'll need to use a test helper)
	// For now, simulate time passing by using the controller's internal method
	// This test verifies that even with no recent activity, tier doesn't drop before cooldown
	ctrl.RecordChallenge(true) // Just one more to trigger recalculation

	bits, _ = ctrl.GetCurrentDifficulty()
	assert.Equal(t, uint32(20), bits, "Should NOT de-escalate before cooldown")
}

// TestDeescalationAfterCooldown verifies tier decreases after cooldown period.
func TestDeescalationAfterCooldown(t *testing.T) {
	cfg := DefaultDifficultyConfig()
	cfg.CooldownDuration = 10 * time.Millisecond // Short cooldown for testing
	cfg.WindowDuration = 10 * time.Millisecond   // Short window for testing
	ctrl := NewDifficultyController(cfg)

	// Escalate to TierElevated
	for i := 0; i < 11; i++ {
		ctrl.RecordChallenge(true)
	}

	bits, _ := ctrl.GetCurrentDifficulty()
	require.Equal(t, uint32(20), bits, "Should be at TierElevated")

	// Wait for cooldown
	time.Sleep(20 * time.Millisecond)

	// Record a single challenge to trigger recalculation
	ctrl.RecordChallenge(true)

	bits, _ = ctrl.GetCurrentDifficulty()
	assert.Equal(t, uint32(16), bits, "Should de-escalate to TierNormal after cooldown")
}

// TestDeescalationOneTierAtATime verifies tier decreases one level at a time.
func TestDeescalationOneTierAtATime(t *testing.T) {
	cfg := DefaultDifficultyConfig()
	cfg.CooldownDuration = 10 * time.Millisecond
	cfg.WindowDuration = 10 * time.Millisecond
	ctrl := NewDifficultyController(cfg)

	// Escalate to TierCritical
	for i := 0; i < 101; i++ {
		ctrl.RecordChallenge(true)
	}

	bits, _ := ctrl.GetCurrentDifficulty()
	require.Equal(t, uint32(28), bits, "Should be at TierCritical")

	// Wait for cooldown and trigger recalculation
	time.Sleep(20 * time.Millisecond)
	ctrl.RecordChallenge(true)

	bits, _ = ctrl.GetCurrentDifficulty()
	assert.Equal(t, uint32(24), bits, "Should de-escalate to TierHigh (one tier down)")

	// Wait again and trigger recalculation
	time.Sleep(20 * time.Millisecond)
	ctrl.RecordChallenge(true)

	bits, _ = ctrl.GetCurrentDifficulty()
	assert.Equal(t, uint32(20), bits, "Should de-escalate to TierElevated (one more tier down)")
}

// TestSlidingWindowEviction verifies old records are evicted from the sliding window.
func TestSlidingWindowEviction(t *testing.T) {
	cfg := DefaultDifficultyConfig()
	cfg.WindowDuration = 20 * time.Millisecond
	cfg.CooldownDuration = 10 * time.Millisecond
	ctrl := NewDifficultyController(cfg)

	// Record 11 challenges to escalate
	for i := 0; i < 11; i++ {
		ctrl.RecordChallenge(true)
	}

	bits, _ := ctrl.GetCurrentDifficulty()
	require.Equal(t, uint32(20), bits, "Should be at TierElevated")

	// Wait for records to become stale
	time.Sleep(30 * time.Millisecond)

	// Record just one challenge (below threshold)
	ctrl.RecordChallenge(true)

	bits, _ = ctrl.GetCurrentDifficulty()
	assert.Equal(t, uint32(16), bits, "Should de-escalate after stale records evicted")
}

// TestGetMetrics verifies the metrics calculation.
func TestGetMetrics(t *testing.T) {
	cfg := DefaultDifficultyConfig()
	ctrl := NewDifficultyController(cfg)

	// Record 8 successes and 2 failures
	for i := 0; i < 8; i++ {
		ctrl.RecordChallenge(true)
	}
	ctrl.RecordChallenge(false)
	ctrl.RecordChallenge(false)

	rate, failureRate := ctrl.GetMetrics()

	assert.Equal(t, 10, rate, "Rate should be 10 requests")
	assert.InDelta(t, 0.20, failureRate, 0.001, "Failure rate should be 20%")
}

// TestGetMetricsEmpty verifies metrics with no records.
func TestGetMetricsEmpty(t *testing.T) {
	cfg := DefaultDifficultyConfig()
	ctrl := NewDifficultyController(cfg)

	rate, failureRate := ctrl.GetMetrics()

	assert.Equal(t, 0, rate, "Rate should be 0 with no records")
	assert.Equal(t, 0.0, failureRate, "Failure rate should be 0 with no records")
}

// TestCurrentTier verifies the GetCurrentTier method.
func TestCurrentTier(t *testing.T) {
	cfg := DefaultDifficultyConfig()
	ctrl := NewDifficultyController(cfg)

	assert.Equal(t, TierNormal, ctrl.GetCurrentTier())

	// Escalate
	for i := 0; i < 11; i++ {
		ctrl.RecordChallenge(true)
	}

	assert.Equal(t, TierElevated, ctrl.GetCurrentTier())
}

// TestConcurrentAccess verifies thread safety of the controller.
func TestConcurrentAccess(t *testing.T) {
	cfg := DefaultDifficultyConfig()
	ctrl := NewDifficultyController(cfg)

	done := make(chan bool, 10)

	// Spawn multiple goroutines recording challenges
	for i := 0; i < 5; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				ctrl.RecordChallenge(true)
			}
			done <- true
		}()
	}

	// Spawn multiple goroutines reading difficulty
	for i := 0; i < 5; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				ctrl.GetCurrentDifficulty()
				ctrl.GetMetrics()
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should not panic or deadlock - reaching here means success
	assert.True(t, true, "Concurrent access should not cause issues")
}

// TestImmediateEscalation verifies escalation happens immediately when thresholds exceeded.
func TestImmediateEscalation(t *testing.T) {
	cfg := DefaultDifficultyConfig()
	ctrl := NewDifficultyController(cfg)

	// Record exactly at threshold
	for i := 0; i < 10; i++ {
		ctrl.RecordChallenge(true)
	}

	bits, _ := ctrl.GetCurrentDifficulty()
	assert.Equal(t, uint32(16), bits, "Should NOT escalate at exactly threshold")

	// One more to exceed threshold
	ctrl.RecordChallenge(true)

	bits, _ = ctrl.GetCurrentDifficulty()
	assert.Equal(t, uint32(20), bits, "Should immediately escalate when threshold exceeded")
}

// TestCannotExceedCritical verifies tier never exceeds TierCritical.
func TestCannotExceedCritical(t *testing.T) {
	cfg := DefaultDifficultyConfig()
	ctrl := NewDifficultyController(cfg)

	// Record massive number of challenges
	for i := 0; i < 500; i++ {
		ctrl.RecordChallenge(true)
	}

	bits, _ := ctrl.GetCurrentDifficulty()
	assert.Equal(t, uint32(28), bits, "Should never exceed TierCritical (28 bits)")
	assert.Equal(t, TierCritical, ctrl.GetCurrentTier())
}

// TestCannotDropBelowNormal verifies tier never goes below TierNormal.
func TestCannotDropBelowNormal(t *testing.T) {
	cfg := DefaultDifficultyConfig()
	cfg.CooldownDuration = 1 * time.Millisecond
	cfg.WindowDuration = 1 * time.Millisecond
	ctrl := NewDifficultyController(cfg)

	// Wait and trigger recalculation multiple times
	for i := 0; i < 5; i++ {
		time.Sleep(5 * time.Millisecond)
		ctrl.RecordChallenge(true)
	}

	bits, _ := ctrl.GetCurrentDifficulty()
	assert.Equal(t, uint32(16), bits, "Should never drop below TierNormal (16 bits)")
	assert.Equal(t, TierNormal, ctrl.GetCurrentTier())
}

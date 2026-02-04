// Package zkproof provides a service layer for zero-knowledge proof functionality.
package zkproof

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultZKConfig(t *testing.T) {
	config := DefaultZKConfig()

	// Verify default values match specification
	assert.False(t, config.Enabled, "ZK should be disabled by default (opt-in)")
	assert.False(t, config.RequireZK, "RequireZK should be false by default")
	assert.True(t, config.PreferZK, "PreferZK should be true by default")
	assert.Equal(t, 30*time.Second, config.ProofTimeout, "default proof timeout should be 30s")
	assert.Equal(t, uint32(64), config.MaxDistance, "default max distance should be 64 (25% of 256)")
	assert.Equal(t, 2, config.ProverWorkers, "default prover workers should be 2")
}

func TestNewZKService_Disabled(t *testing.T) {
	// When ZK is disabled, service should be created without compiling circuit
	config := DefaultZKConfig()
	config.Enabled = false

	svc, err := NewZKService(config)
	require.NoError(t, err)
	require.NotNil(t, svc)

	// Service should not be enabled even though it exists
	assert.False(t, svc.IsEnabled(), "disabled service should report IsEnabled=false")

	// Internal components should be nil
	assert.Nil(t, svc.GetProver(), "disabled service should have nil prover")
	assert.Nil(t, svc.GetVerifier(), "disabled service should have nil verifier")
}

func TestNewZKService_Enabled(t *testing.T) {
	// Skip in short mode as circuit compilation is slow
	if testing.Short() {
		t.Skip("skipping test in short mode (circuit compilation is slow)")
	}

	config := DefaultZKConfig()
	config.Enabled = true

	svc, err := NewZKService(config)
	require.NoError(t, err)
	require.NotNil(t, svc)

	// Service should be fully enabled
	assert.True(t, svc.IsEnabled(), "enabled service should report IsEnabled=true")

	// Internal components should be initialized
	assert.NotNil(t, svc.GetProver(), "enabled service should have non-nil prover")
	assert.NotNil(t, svc.GetVerifier(), "enabled service should have non-nil verifier")
}

func TestZKService_IsEnabled(t *testing.T) {
	t.Run("disabled_config", func(t *testing.T) {
		config := DefaultZKConfig()
		config.Enabled = false

		svc, err := NewZKService(config)
		require.NoError(t, err)

		assert.False(t, svc.IsEnabled())
	})

	t.Run("enabled_config", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode")
		}

		config := DefaultZKConfig()
		config.Enabled = true

		svc, err := NewZKService(config)
		require.NoError(t, err)

		assert.True(t, svc.IsEnabled())
	})
}

func TestZKService_RequiresZK(t *testing.T) {
	config := DefaultZKConfig()

	t.Run("require_false", func(t *testing.T) {
		config.RequireZK = false
		svc, err := NewZKService(config)
		require.NoError(t, err)

		assert.False(t, svc.RequiresZK())
	})

	t.Run("require_true", func(t *testing.T) {
		config.RequireZK = true
		svc, err := NewZKService(config)
		require.NoError(t, err)

		assert.True(t, svc.RequiresZK())
	})
}

func TestZKService_PrefersZK(t *testing.T) {
	config := DefaultZKConfig()

	t.Run("prefer_false", func(t *testing.T) {
		config.PreferZK = false
		svc, err := NewZKService(config)
		require.NoError(t, err)

		assert.False(t, svc.PrefersZK())
	})

	t.Run("prefer_true", func(t *testing.T) {
		config.PreferZK = true
		svc, err := NewZKService(config)
		require.NoError(t, err)

		assert.True(t, svc.PrefersZK())
	})
}

func TestZKService_GetConfig(t *testing.T) {
	config := ZKConfig{
		Enabled:       true,
		RequireZK:     true,
		PreferZK:      false,
		ProofTimeout:  45 * time.Second,
		MaxDistance:   128,
		ProverWorkers: 4,
	}

	// For this test, we don't actually need to enable the circuit compilation
	// Just test that the config is stored and returned correctly
	testConfig := config
	testConfig.Enabled = false // Disable to avoid slow compilation

	svc, err := NewZKService(testConfig)
	require.NoError(t, err)

	returnedConfig := svc.GetConfig()
	assert.Equal(t, testConfig, returnedConfig)
}

func TestZKService_Metrics(t *testing.T) {
	config := DefaultZKConfig()
	svc, err := NewZKService(config)
	require.NoError(t, err)

	// Initial state should be all zeros
	generated, verified, failed := svc.Stats()
	assert.Equal(t, uint64(0), generated)
	assert.Equal(t, uint64(0), verified)
	assert.Equal(t, uint64(0), failed)

	// Record some events
	svc.RecordProofGenerated()
	svc.RecordProofGenerated()
	svc.RecordProofVerified()
	svc.RecordProofFailed()

	// Verify updated stats
	generated, verified, failed = svc.Stats()
	assert.Equal(t, uint64(2), generated)
	assert.Equal(t, uint64(1), verified)
	assert.Equal(t, uint64(1), failed)
}

func TestZKService_MetricsConcurrency(t *testing.T) {
	config := DefaultZKConfig()
	svc, err := NewZKService(config)
	require.NoError(t, err)

	// Run concurrent metric updates
	const goroutines = 10
	const operations = 100

	done := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			for j := 0; j < operations; j++ {
				svc.RecordProofGenerated()
				svc.RecordProofVerified()
				svc.RecordProofFailed()
			}
			done <- struct{}{}
		}()
	}

	// Wait for all goroutines
	for i := 0; i < goroutines; i++ {
		<-done
	}

	// Verify final counts
	generated, verified, failed := svc.Stats()
	expectedCount := uint64(goroutines * operations)
	assert.Equal(t, expectedCount, generated)
	assert.Equal(t, expectedCount, verified)
	assert.Equal(t, expectedCount, failed)
}

func TestZKConfig_Validate(t *testing.T) {
	t.Run("valid_disabled_config", func(t *testing.T) {
		// Validation applies to all fields regardless of Enabled state
		config := DefaultZKConfig()
		config.Enabled = false
		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid_enabled_config", func(t *testing.T) {
		config := DefaultZKConfig()
		config.Enabled = true
		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("invalid_proof_timeout_zero", func(t *testing.T) {
		config := DefaultZKConfig()
		config.ProofTimeout = 0
		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "proof_timeout")
	})

	t.Run("invalid_proof_timeout_negative", func(t *testing.T) {
		config := DefaultZKConfig()
		config.ProofTimeout = -5 * time.Second
		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "proof_timeout")
	})

	t.Run("invalid_max_distance_zero", func(t *testing.T) {
		config := DefaultZKConfig()
		config.MaxDistance = 0
		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "max_distance")
	})

	t.Run("valid_max_distance_boundary_256", func(t *testing.T) {
		config := DefaultZKConfig()
		config.MaxDistance = 256 // Maximum valid value
		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("invalid_max_distance_exceeds_limit", func(t *testing.T) {
		config := DefaultZKConfig()
		config.MaxDistance = 257
		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "max_distance")
	})

	t.Run("invalid_prover_workers_zero", func(t *testing.T) {
		config := DefaultZKConfig()
		config.ProverWorkers = 0
		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "prover_workers")
	})

	t.Run("invalid_prover_workers_negative", func(t *testing.T) {
		config := DefaultZKConfig()
		config.ProverWorkers = -1
		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "prover_workers")
	})

	t.Run("validates_disabled_config_fields", func(t *testing.T) {
		// Even disabled configs must have valid field values
		config := ZKConfig{
			Enabled:       false,
			ProofTimeout:  0, // Invalid
			MaxDistance:   64,
			ProverWorkers: 2,
		}
		err := config.Validate()
		assert.Error(t, err, "disabled config with invalid fields should fail validation")
	})
}

func TestZKConfig_String(t *testing.T) {
	t.Run("disabled_config", func(t *testing.T) {
		config := ZKConfig{Enabled: false}
		str := config.String()
		assert.Contains(t, str, "Enabled: false")
	})

	t.Run("enabled_config", func(t *testing.T) {
		config := ZKConfig{
			Enabled:      true,
			RequireZK:    true,
			PreferZK:     false,
			MaxDistance:  64,
			ProofTimeout: 30 * time.Second,
		}
		str := config.String()
		assert.Contains(t, str, "Enabled: true")
		assert.Contains(t, str, "RequireZK: true")
		assert.Contains(t, str, "PreferZK: false")
		assert.Contains(t, str, "MaxDistance: 64")
		assert.Contains(t, str, "Timeout: 30s")
	})
}

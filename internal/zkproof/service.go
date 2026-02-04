// Package zkproof provides a service layer for zero-knowledge proof functionality.
//
// ZKService wraps the low-level circuit compilation, proving, and verification
// components to provide a high-level interface for the P2P protocol.
//
// # Usage
//
// The service is configured via ZKConfig which controls:
//   - Whether ZK proofs are enabled at all
//   - Whether ZK proofs are required from peers
//   - Whether ZK-capable peers are preferred over plaintext
//
// # Thread Safety
//
// ZKService is safe for concurrent use from multiple goroutines.
// Metrics are tracked using atomic operations.
package zkproof

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/mymonad/mymonad/pkg/zkproof"
)

// ZKConfig contains configuration for the ZK proof service.
type ZKConfig struct {
	// Enabled determines whether this node advertises and accepts ZK proofs.
	// When false, the circuit is not compiled and proof operations are unavailable.
	// This is opt-in by default.
	Enabled bool `toml:"enabled"`

	// RequireZK when true rejects peers that do not provide ZK proofs.
	// This provides maximum privacy but limits connectivity.
	RequireZK bool `toml:"require_zk"`

	// PreferZK when true prefers ZK-capable peers but accepts plaintext fallback.
	// This provides privacy when possible while maintaining broader connectivity.
	PreferZK bool `toml:"prefer_zk"`

	// ProofTimeout is the maximum time to wait for a peer to provide a proof.
	ProofTimeout time.Duration `toml:"proof_timeout"`

	// MaxDistance is the default Hamming distance threshold for proofs.
	// Proofs demonstrate that two signatures are within this distance.
	MaxDistance uint32 `toml:"max_distance"`

	// ProverWorkers is the number of parallel workers for proof generation.
	// More workers allow concurrent proof generation at the cost of memory.
	ProverWorkers int `toml:"prover_workers"`
}

// DefaultZKConfig returns a ZKConfig with sensible defaults.
//
// Default behavior:
//   - ZK disabled (opt-in for privacy)
//   - Prefer ZK peers when available
//   - 30 second timeout for proof generation
//   - 64 bit max distance (25% of 256-bit signature)
//   - 2 parallel prover workers
func DefaultZKConfig() ZKConfig {
	return ZKConfig{
		Enabled:       false, // Opt-in
		RequireZK:     false,
		PreferZK:      true,
		ProofTimeout:  30 * time.Second,
		MaxDistance:   64, // 25% of 256 bits
		ProverWorkers: 2,
	}
}

// Validate checks the configuration for errors.
// Returns an error describing any invalid configuration values.
func (c ZKConfig) Validate() error {
	if c.Enabled {
		if c.ProofTimeout <= 0 {
			return fmt.Errorf("zkconfig: proof_timeout must be positive")
		}
		if c.MaxDistance == 0 || c.MaxDistance > 256 {
			return fmt.Errorf("zkconfig: max_distance must be between 1 and 256")
		}
		if c.ProverWorkers <= 0 {
			return fmt.Errorf("zkconfig: prover_workers must be positive")
		}
	}
	return nil
}

// String returns a human-readable representation of the config.
func (c ZKConfig) String() string {
	if !c.Enabled {
		return "ZKConfig{Enabled: false}"
	}
	return fmt.Sprintf("ZKConfig{Enabled: true, RequireZK: %v, PreferZK: %v, MaxDistance: %d, Timeout: %v}",
		c.RequireZK, c.PreferZK, c.MaxDistance, c.ProofTimeout)
}

// ZKService provides zero-knowledge proof functionality for the P2P protocol.
//
// The service manages circuit compilation, proof generation, and verification.
// It tracks metrics for monitoring proof operations.
type ZKService struct {
	config   ZKConfig
	compiled *zkproof.CompiledCircuit
	prover   *zkproof.Prover
	verifier *zkproof.Verifier

	// Metrics tracked atomically
	proofsGenerated uint64
	proofsVerified  uint64
	proofsFailed    uint64
}

// NewZKService creates a new ZKService with the given configuration.
//
// When config.Enabled is false, the service is created in a disabled state
// without compiling the circuit. This allows the service to exist without
// incurring the cost of circuit compilation.
//
// When config.Enabled is true, the circuit is compiled at startup.
// This is a computationally expensive operation that takes several seconds.
func NewZKService(config ZKConfig) (*ZKService, error) {
	svc := &ZKService{
		config: config,
	}

	if !config.Enabled {
		return svc, nil
	}

	// Compile circuit at startup (expensive operation)
	compiled, err := zkproof.CompileCircuit()
	if err != nil {
		return nil, fmt.Errorf("compile circuit: %w", err)
	}

	svc.compiled = compiled
	svc.prover = zkproof.NewProver(compiled)
	svc.verifier = zkproof.NewVerifier(compiled)

	return svc, nil
}

// IsEnabled returns true if ZK proofs are enabled and the circuit is compiled.
//
// A service can be created with Enabled=true but still return false here
// if circuit compilation failed. Always check this before using the service.
func (zk *ZKService) IsEnabled() bool {
	return zk.config.Enabled && zk.compiled != nil
}

// RequiresZK returns true if this node requires ZK proofs from peers.
//
// When true, connections from peers that do not provide ZK proofs will be rejected.
func (zk *ZKService) RequiresZK() bool {
	return zk.config.RequireZK
}

// PrefersZK returns true if this node prefers ZK-capable peers.
//
// When true, the node will prefer connecting to ZK-capable peers but
// will accept plaintext connections as a fallback.
func (zk *ZKService) PrefersZK() bool {
	return zk.config.PreferZK
}

// GetProver returns the prover instance, or nil if ZK is disabled.
func (zk *ZKService) GetProver() *zkproof.Prover {
	return zk.prover
}

// GetVerifier returns the verifier instance, or nil if ZK is disabled.
func (zk *ZKService) GetVerifier() *zkproof.Verifier {
	return zk.verifier
}

// GetConfig returns a copy of the service configuration.
func (zk *ZKService) GetConfig() ZKConfig {
	return zk.config
}

// RecordProofGenerated increments the proof generation counter.
// This should be called after successfully generating a proof.
func (zk *ZKService) RecordProofGenerated() {
	atomic.AddUint64(&zk.proofsGenerated, 1)
}

// RecordProofVerified increments the successful verification counter.
// This should be called after successfully verifying a proof.
func (zk *ZKService) RecordProofVerified() {
	atomic.AddUint64(&zk.proofsVerified, 1)
}

// RecordProofFailed increments the failure counter.
// This should be called when proof generation or verification fails.
func (zk *ZKService) RecordProofFailed() {
	atomic.AddUint64(&zk.proofsFailed, 1)
}

// Stats returns the current metrics for proof operations.
//
// Returns:
//   - generated: number of proofs successfully generated
//   - verified: number of proofs successfully verified
//   - failed: number of proof operations that failed
func (zk *ZKService) Stats() (generated, verified, failed uint64) {
	return atomic.LoadUint64(&zk.proofsGenerated),
		atomic.LoadUint64(&zk.proofsVerified),
		atomic.LoadUint64(&zk.proofsFailed)
}

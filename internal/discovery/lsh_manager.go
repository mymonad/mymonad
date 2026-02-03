// Package discovery provides peer discovery mechanisms for the P2P network.
// The LSHDiscoveryManager handles rate limiting, retry logic, and peer management
// for LSH-based peer discovery. It enforces the 1/minute handshake initiation
// rate limit to prevent spam.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mymonad/mymonad/pkg/lsh"
)

// Retry logic constants
const (
	// MaxExchangeRetries is the maximum number of times to retry a failed exchange.
	MaxExchangeRetries = 3
	// RetryBackoffBase is the initial backoff duration for retries.
	RetryBackoffBase = 5 * time.Second
	// RetryBackoffMax is the maximum backoff duration for retries.
	RetryBackoffMax = 60 * time.Second
)

// Error messages for LSHDiscoveryManager
var (
	// ErrNoLocalSignature is returned when trying to create an exchange without a local signature.
	ErrNoLocalSignature = errors.New("no local signature set")
	// ErrMaxPendingExchanges is returned when the maximum number of pending exchanges is reached.
	ErrMaxPendingExchanges = errors.New("maximum pending exchanges reached")
)

// LSHDiscoveryConfig holds configuration for the LSHDiscoveryManager.
type LSHDiscoveryConfig struct {
	// HammingThreshold is the maximum Hamming distance for considering peers similar.
	// Default: 64 (25% of 256 bits)
	HammingThreshold int

	// InitiationRateLimit is the minimum time between handshake initiations.
	// Default: 1 minute
	InitiationRateLimit time.Duration

	// ExchangeTimeout is the maximum time for a commit-reveal exchange.
	// Default: 30 seconds
	ExchangeTimeout time.Duration

	// MaxPendingExchanges limits concurrent exchanges to prevent resource exhaustion.
	// Default: 10
	MaxPendingExchanges int
}

// DefaultLSHDiscoveryConfig returns the default configuration for LSHDiscoveryManager.
func DefaultLSHDiscoveryConfig() LSHDiscoveryConfig {
	return LSHDiscoveryConfig{
		HammingThreshold:    64, // 25% of 256 bits
		InitiationRateLimit: time.Minute,
		ExchangeTimeout:     30 * time.Second,
		MaxPendingExchanges: 10,
	}
}

// DiscoveredPeer represents a peer discovered through LSH signature exchange.
type DiscoveredPeer struct {
	// PeerID is the libp2p peer identifier.
	PeerID peer.ID
	// Signature is the peer's LSH signature.
	Signature []byte
	// HammingDistance is the Hamming distance between local and peer signatures.
	HammingDistance int
	// DiscoveredAt is when this peer was first discovered.
	DiscoveredAt time.Time
	// LastExchange is the timestamp of the last successful exchange with this peer.
	LastExchange time.Time
}

// LSHDiscoveryManager coordinates LSH-based peer discovery with rate limiting
// and retry logic. It is thread-safe for concurrent use.
type LSHDiscoveryManager struct {
	mu               sync.RWMutex
	localSignature   []byte
	discoveredPeers  map[peer.ID]*DiscoveredPeer
	pendingExchanges map[peer.ID]*Exchange
	lastInitiation   time.Time
	config           LSHDiscoveryConfig
}

// NewLSHDiscoveryManager creates a new LSHDiscoveryManager with the given configuration.
func NewLSHDiscoveryManager(config LSHDiscoveryConfig) *LSHDiscoveryManager {
	return &LSHDiscoveryManager{
		discoveredPeers:  make(map[peer.ID]*DiscoveredPeer),
		pendingExchanges: make(map[peer.ID]*Exchange),
		config:           config,
	}
}

// Config returns the manager's configuration.
func (dm *LSHDiscoveryManager) Config() LSHDiscoveryConfig {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.config
}

// SetLocalSignature updates the local LSH signature.
// The signature is copied to prevent external modifications.
func (dm *LSHDiscoveryManager) SetLocalSignature(sig []byte) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if sig == nil {
		dm.localSignature = nil
		return
	}

	// Copy to prevent external modifications
	dm.localSignature = make([]byte, len(sig))
	copy(dm.localSignature, sig)
}

// GetLocalSignature returns a copy of the local signature.
// Returns nil if no signature has been set.
func (dm *LSHDiscoveryManager) GetLocalSignature() []byte {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	if dm.localSignature == nil {
		return nil
	}

	// Return a copy to prevent external modifications
	result := make([]byte, len(dm.localSignature))
	copy(result, dm.localSignature)
	return result
}

// CanInitiateHandshake checks if a new handshake initiation is allowed
// based on the rate limit. Returns true if at least InitiationRateLimit
// has passed since the last initiation.
func (dm *LSHDiscoveryManager) CanInitiateHandshake() bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	// If we've never initiated, allow it
	if dm.lastInitiation.IsZero() {
		return true
	}

	return time.Since(dm.lastInitiation) >= dm.config.InitiationRateLimit
}

// RecordHandshakeInitiation updates the last initiation time to now.
// Call this after successfully starting a handshake initiation.
func (dm *LSHDiscoveryManager) RecordHandshakeInitiation() {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.lastInitiation = time.Now()
}

// ShouldRetry determines if an exchange should be retried based on the error type.
// Protocol violations (commitment mismatch, invalid salt, malformed signature)
// should not be retried as they indicate a misbehaving peer.
// Transient errors (stale timestamp, rate limited) can be retried.
func (dm *LSHDiscoveryManager) ShouldRetry(err DiscoveryError) bool {
	switch err {
	case ErrCommitmentMismatch, ErrInvalidSalt, ErrMalformedSignature:
		// Protocol violations - no retry
		return false
	case ErrStaleTimestamp, ErrRateLimited:
		// Transient errors - can retry
		return true
	default:
		// Unknown errors - no retry
		return false
	}
}

// RetryBackoff calculates the backoff duration for a given retry count.
// Uses exponential backoff starting at RetryBackoffBase (5s) with a maximum
// of RetryBackoffMax (60s).
func (dm *LSHDiscoveryManager) RetryBackoff(retryCount int) time.Duration {
	if retryCount < 0 {
		retryCount = 0
	}

	// Exponential backoff: base * 2^retryCount
	backoff := RetryBackoffBase * time.Duration(1<<uint(retryCount))

	if backoff > RetryBackoffMax {
		return RetryBackoffMax
	}
	return backoff
}

// IsWithinThreshold checks if a Hamming distance is within the configured threshold.
func (dm *LSHDiscoveryManager) IsWithinThreshold(hammingDistance int) bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return hammingDistance <= dm.config.HammingThreshold
}

// AddDiscoveredPeer adds or updates a discovered peer.
// The signature is copied to prevent external modifications.
func (dm *LSHDiscoveryManager) AddDiscoveredPeer(peerID peer.ID, signature []byte, hammingDistance int) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	now := time.Now()

	// Copy signature
	sigCopy := make([]byte, len(signature))
	copy(sigCopy, signature)

	existing := dm.discoveredPeers[peerID]
	if existing != nil {
		// Update existing peer
		existing.Signature = sigCopy
		existing.HammingDistance = hammingDistance
		existing.LastExchange = now
	} else {
		// Add new peer
		dm.discoveredPeers[peerID] = &DiscoveredPeer{
			PeerID:          peerID,
			Signature:       sigCopy,
			HammingDistance: hammingDistance,
			DiscoveredAt:    now,
			LastExchange:    now,
		}
	}
}

// GetDiscoveredPeer returns the discovered peer info for the given peer ID.
// Returns nil if the peer has not been discovered.
func (dm *LSHDiscoveryManager) GetDiscoveredPeer(peerID peer.ID) *DiscoveredPeer {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.discoveredPeers[peerID]
}

// RemoveDiscoveredPeer removes a peer from the discovered peers map.
func (dm *LSHDiscoveryManager) RemoveDiscoveredPeer(peerID peer.ID) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	delete(dm.discoveredPeers, peerID)
}

// GetDiscoveredPeerCount returns the number of discovered peers.
func (dm *LSHDiscoveryManager) GetDiscoveredPeerCount() int {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return len(dm.discoveredPeers)
}

// ListDiscoveredPeers returns a slice of all discovered peers.
// The returned slice is a copy and safe to modify.
func (dm *LSHDiscoveryManager) ListDiscoveredPeers() []*DiscoveredPeer {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	result := make([]*DiscoveredPeer, 0, len(dm.discoveredPeers))
	for _, p := range dm.discoveredPeers {
		result = append(result, p)
	}
	return result
}

// AddPendingExchange creates and adds a new pending exchange for the given peer.
// Returns an error if no local signature is set or if the maximum number of
// pending exchanges has been reached.
func (dm *LSHDiscoveryManager) AddPendingExchange(peerID peer.ID, role ExchangeRole) (*Exchange, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if dm.localSignature == nil {
		return nil, ErrNoLocalSignature
	}

	if len(dm.pendingExchanges) >= dm.config.MaxPendingExchanges {
		return nil, ErrMaxPendingExchanges
	}

	// Create exchange with a copy of the local signature
	exchange, err := NewExchange(peerID, role, dm.localSignature)
	if err != nil {
		return nil, err
	}

	dm.pendingExchanges[peerID] = exchange
	return exchange, nil
}

// GetPendingExchange returns the pending exchange for the given peer ID.
// Returns nil if no exchange is pending with that peer.
func (dm *LSHDiscoveryManager) GetPendingExchange(peerID peer.ID) *Exchange {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.pendingExchanges[peerID]
}

// RemovePendingExchange removes a pending exchange for the given peer.
func (dm *LSHDiscoveryManager) RemovePendingExchange(peerID peer.ID) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	delete(dm.pendingExchanges, peerID)
}

// GetPendingExchangeCount returns the number of pending exchanges.
func (dm *LSHDiscoveryManager) GetPendingExchangeCount() int {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return len(dm.pendingExchanges)
}

// CleanupExpiredExchanges removes all expired pending exchanges.
// Returns the number of exchanges removed.
func (dm *LSHDiscoveryManager) CleanupExpiredExchanges() int {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	var removed int
	for peerID, exchange := range dm.pendingExchanges {
		if exchange.IsExpired() {
			delete(dm.pendingExchanges, peerID)
			removed++
		}
	}
	return removed
}

// GetPendingExchangeWithExists returns the pending exchange for the given peer ID
// along with a boolean indicating whether the exchange exists.
func (dm *LSHDiscoveryManager) GetPendingExchangeWithExists(peerID peer.ID) (*Exchange, bool) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	ex, exists := dm.pendingExchanges[peerID]
	return ex, exists
}

// ShouldInitiateExchange determines if we should initiate an exchange with a peer.
// The peer with the lexicographically lower ID initiates to avoid deadlock.
// If IDs are equal, neither initiates (should not happen in practice).
func (dm *LSHDiscoveryManager) ShouldInitiateExchange(localID, remoteID peer.ID) bool {
	return shouldInitiate(localID, remoteID)
}

// InitiateExchange starts a signature exchange with a discovered peer.
// Returns an error if an exchange is already pending with the peer,
// if the maximum pending exchanges limit is reached, or if no local
// signature is set.
func (dm *LSHDiscoveryManager) InitiateExchange(peerID peer.ID) (*Exchange, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Check if no local signature
	if dm.localSignature == nil {
		return nil, ErrNoLocalSignature
	}

	// Check if already have pending exchange
	if _, exists := dm.pendingExchanges[peerID]; exists {
		return nil, fmt.Errorf("exchange already pending with peer %s", peerID)
	}

	// Check max pending limit
	if len(dm.pendingExchanges) >= dm.config.MaxPendingExchanges {
		return nil, fmt.Errorf("max pending exchanges reached")
	}

	// Create new exchange
	ex, err := NewExchange(peerID, RoleInitiator, dm.localSignature)
	if err != nil {
		return nil, err
	}

	dm.pendingExchanges[peerID] = ex
	return ex, nil
}

// CompleteExchange marks an exchange as complete and records the discovered peer.
// The peer signature is copied to prevent external modifications.
func (dm *LSHDiscoveryManager) CompleteExchange(peerID peer.ID, peerSignature []byte, hammingDistance int) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Remove from pending
	delete(dm.pendingExchanges, peerID)

	// Copy signature to prevent external modifications
	sigCopy := make([]byte, len(peerSignature))
	copy(sigCopy, peerSignature)

	now := time.Now()

	// Record discovered peer
	existing := dm.discoveredPeers[peerID]
	if existing != nil {
		// Update existing peer
		existing.Signature = sigCopy
		existing.HammingDistance = hammingDistance
		existing.LastExchange = now
	} else {
		// Add new peer
		dm.discoveredPeers[peerID] = &DiscoveredPeer{
			PeerID:          peerID,
			Signature:       sigCopy,
			HammingDistance: hammingDistance,
			DiscoveredAt:    now,
			LastExchange:    now,
		}
	}
}

// FailExchange marks an exchange as failed and cleans up.
// If the exchange exists, its state is set to ExchangeStateFailed
// before removal from pending exchanges.
func (dm *LSHDiscoveryManager) FailExchange(peerID peer.ID, reason error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if ex, exists := dm.pendingExchanges[peerID]; exists {
		ex.State = ExchangeStateFailed
		delete(dm.pendingExchanges, peerID)
	}
}

// DiscoveryLoop runs the periodic discovery process.
// It queries the DHT bucket for peers and initiates exchanges
// with discovered peers. The loop runs until the context is cancelled.
func (dm *LSHDiscoveryManager) DiscoveryLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dm.discoverBucketPeers(ctx)
		}
	}
}

// discoverBucketPeers queries the DHT and initiates exchanges with new peers.
// This is called periodically by DiscoveryLoop.
func (dm *LSHDiscoveryManager) discoverBucketPeers(ctx context.Context) {
	// Get bucket ID from local signature
	bucketID := lsh.DeriveBucketID(dm.GetLocalSignature())
	if bucketID == "" {
		return // No signature set yet
	}

	// In production: query DHT for peers in bucket
	// For now: this will be called by DHT discovery callback
	// The actual DHT query implementation is in the dht.go file
}

// Package antispam provides load-adaptive spam prevention for the MyMonad P2P protocol.
package antispam

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"

	"github.com/libp2p/go-libp2p/core/peer"
)

// NonceStore manages challenge nonces for the anti-spam proof-of-work system.
// It handles nonce generation, validation, replay prevention, and automatic cleanup.
//
// The store is safe for concurrent use.
type NonceStore struct {
	mu     sync.RWMutex
	nonces map[string]*nonceRecord // Keyed by hex(nonce)

	// Cleanup configuration
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	stopped         bool
}

// nonceRecord represents a stored challenge nonce with its metadata.
type nonceRecord struct {
	nonce      []byte
	difficulty uint32
	createdAt  time.Time
	expiresAt  time.Time
	peerID     peer.ID
	used       bool // Prevents replay attacks
}

const (
	// NonceLength is the length of generated nonces in bytes.
	NonceLength = 16

	// CleanupInterval is the default interval for the cleanup loop.
	CleanupInterval = 30 * time.Second

	// MaxPendingNonces is the maximum number of pending nonces allowed.
	// This prevents memory exhaustion from excessive challenge generation.
	MaxPendingNonces = 10000
)

// Errors returned by the NonceStore.
var (
	ErrUnknownNonce      = errors.New("unknown nonce")
	ErrNonceBoundToPeer  = errors.New("nonce bound to different peer")
	ErrNonceExpired      = errors.New("nonce expired")
	ErrNonceAlreadyUsed  = errors.New("nonce already used")
	ErrStoreAtCapacity   = errors.New("nonce store at capacity")
)

// NewNonceStore creates a new NonceStore with default cleanup interval.
// The cleanup goroutine is started automatically.
func NewNonceStore() *NonceStore {
	return NewNonceStoreWithCleanupInterval(CleanupInterval)
}

// NewNonceStoreWithCleanupInterval creates a new NonceStore with a custom cleanup interval.
// This is useful for testing with shorter intervals.
func NewNonceStoreWithCleanupInterval(cleanupInterval time.Duration) *NonceStore {
	store := &NonceStore{
		nonces:          make(map[string]*nonceRecord),
		cleanupInterval: cleanupInterval,
		stopCleanup:     make(chan struct{}),
		stopped:         false,
	}

	go store.cleanupLoop()

	return store
}

// GenerateChallenge creates a new PoW challenge bound to the specified peer.
// It generates a cryptographically random nonce and stores it for later validation.
//
// Returns an error if the store is at capacity (MaxPendingNonces).
func (ns *NonceStore) GenerateChallenge(peerID peer.ID, difficulty uint32, expiration time.Duration) (*pb.PoWChallenge, error) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	// Check capacity
	if len(ns.nonces) >= MaxPendingNonces {
		return nil, ErrStoreAtCapacity
	}

	// Generate random nonce
	nonce := make([]byte, NonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	now := time.Now()

	// Create the record
	record := &nonceRecord{
		nonce:      nonce,
		difficulty: difficulty,
		createdAt:  now,
		expiresAt:  now.Add(expiration),
		peerID:     peerID,
		used:       false,
	}

	// Store the record keyed by hex-encoded nonce
	nonceKey := hex.EncodeToString(nonce)
	ns.nonces[nonceKey] = record

	// Create and return the challenge proto
	challenge := &pb.PoWChallenge{
		Nonce:      nonce,
		Timestamp:  now.UnixMilli(),
		Difficulty: difficulty,
		PeerId:     []byte(peerID),
	}

	return challenge, nil
}

// ValidateAndConsume validates a nonce and marks it as used to prevent replay attacks.
// It checks that:
//   - The nonce exists in the store
//   - The nonce is bound to the requesting peer
//   - The nonce has not expired
//   - The nonce has not been used before
//
// On success, the nonce is marked as used and the record is returned.
// The caller can use the returned record to verify the difficulty requirement.
func (ns *NonceStore) ValidateAndConsume(nonce []byte, peerID peer.ID) (*nonceRecord, error) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	// Handle nil/empty nonce
	if len(nonce) == 0 {
		return nil, ErrUnknownNonce
	}

	// Look up the nonce
	nonceKey := hex.EncodeToString(nonce)
	record, exists := ns.nonces[nonceKey]
	if !exists {
		return nil, ErrUnknownNonce
	}

	// Check peer binding
	if record.peerID != peerID {
		return nil, ErrNonceBoundToPeer
	}

	// Check expiration
	if time.Now().After(record.expiresAt) {
		return nil, ErrNonceExpired
	}

	// Check replay
	if record.used {
		return nil, ErrNonceAlreadyUsed
	}

	// Mark as used
	record.used = true

	return record, nil
}

// cleanupLoop periodically removes expired and used nonces from the store.
// It runs until Stop() is called.
func (ns *NonceStore) cleanupLoop() {
	ticker := time.NewTicker(ns.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ns.stopCleanup:
			return
		case <-ticker.C:
			ns.cleanup()
		}
	}
}

// cleanup removes expired and used nonces from the store.
func (ns *NonceStore) cleanup() {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	now := time.Now()
	for key, record := range ns.nonces {
		// Remove if expired or already used
		if record.used || now.After(record.expiresAt) {
			delete(ns.nonces, key)
		}
	}
}

// Stop stops the cleanup goroutine.
// It is safe to call Stop multiple times.
func (ns *NonceStore) Stop() {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	if !ns.stopped {
		close(ns.stopCleanup)
		ns.stopped = true
	}
}

// Stats returns the current statistics of the nonce store.
// It returns:
//   - total: total number of nonces in the store
//   - pending: number of nonces that are neither expired nor used
//   - used: number of nonces that have been used
func (ns *NonceStore) Stats() (total, pending, used int) {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	now := time.Now()
	total = len(ns.nonces)

	for _, record := range ns.nonces {
		if record.used {
			used++
		} else if now.Before(record.expiresAt) || now.Equal(record.expiresAt) {
			pending++
		}
	}

	return total, pending, used
}

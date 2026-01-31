// Package agent provides peer discovery using LSH signatures published to the DHT.
// This enables O(log n) discovery of peers with similar Monad vectors.
package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mymonad/mymonad/pkg/lsh"
)

// VisibilityMode controls how the agent participates in DHT-based peer discovery.
type VisibilityMode int

const (
	// VisibilityActive publishes LSH buckets to DHT and actively queries for similar peers.
	VisibilityActive VisibilityMode = iota
	// VisibilityPassive publishes LSH buckets to DHT but does not query for peers.
	VisibilityPassive
	// VisibilityHidden does not publish to DHT and does not query for peers.
	VisibilityHidden
)

// DefaultBucketSize is the default number of bits per LSH bucket.
// This determines the granularity of peer discovery - smaller buckets mean
// more specific matching but fewer peers per bucket.
const DefaultBucketSize = 4

// DiscoveryErrorCallback is called when non-fatal errors occur during discovery.
type DiscoveryErrorCallback func(err error)

// Discovery manages LSH-based peer discovery through the DHT.
// It publishes LSH signature buckets to the DHT and discovers peers
// with similar signatures by querying the same bucket keys.
type Discovery struct {
	host       *Host
	dht        *DHT
	visibility VisibilityMode
	signature  *lsh.MonadSignature
	bucketSize int
	onError    DiscoveryErrorCallback
	mu         sync.RWMutex
}

// ErrNilHost is returned when the host is nil.
var ErrNilHost = errors.New("discovery: host cannot be nil")

// ErrNilDHT is returned when the DHT is nil.
var ErrNilDHT = errors.New("discovery: dht cannot be nil")

// NewDiscovery creates a new Discovery instance.
// Returns an error if host or dht is nil.
func NewDiscovery(host *Host, dht *DHT) (*Discovery, error) {
	if host == nil {
		return nil, ErrNilHost
	}
	if dht == nil {
		return nil, ErrNilDHT
	}

	return &Discovery{
		host:       host,
		dht:        dht,
		visibility: VisibilityActive,
		bucketSize: DefaultBucketSize,
	}, nil
}

// SetVisibility changes the visibility mode.
// Changes take effect immediately for subsequent operations.
func (d *Discovery) SetVisibility(mode VisibilityMode) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.visibility = mode
}

// Visibility returns the current visibility mode.
func (d *Discovery) Visibility() VisibilityMode {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.visibility
}

// Signature returns the current LSH signature, or nil if not set.
func (d *Discovery) Signature() *lsh.MonadSignature {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.signature
}

// SetErrorCallback sets a callback function for non-fatal discovery errors.
// This is useful for logging DHT errors that don't prevent discovery from continuing.
func (d *Discovery) SetErrorCallback(cb DiscoveryErrorCallback) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.onError = cb
}

// UpdateSignature sets the LSH signature and publishes buckets to DHT if visibility allows.
// Returns an error if the signature is nil.
// In Hidden mode, the signature is stored locally but not published to the DHT.
func (d *Discovery) UpdateSignature(sig *lsh.MonadSignature) error {
	if sig == nil {
		return errors.New("signature cannot be nil")
	}

	d.mu.Lock()
	d.signature = sig
	d.mu.Unlock()

	return nil
}

// PublishBuckets publishes the LSH signature buckets to the DHT.
// In Hidden mode, this is a no-op and returns nil.
// Returns an error if no signature has been set.
func (d *Discovery) PublishBuckets(ctx context.Context) error {
	d.mu.RLock()
	sig := d.signature
	visibility := d.visibility
	d.mu.RUnlock()

	// In hidden mode, do not publish to DHT
	if visibility == VisibilityHidden {
		return nil
	}

	if sig == nil {
		return errors.New("no signature set")
	}

	// Extract buckets from signature
	buckets := ExtractBuckets(sig.Signature, d.bucketSize)

	// Publish each bucket to DHT
	for prefix, value := range buckets {
		key := BucketToDHTKey(prefix, value)
		if err := d.dht.Provide(ctx, key); err != nil {
			return fmt.Errorf("failed to provide bucket %d: %w", prefix, err)
		}
	}

	return nil
}

// FindSimilar discovers peers with similar LSH signatures.
// Returns up to count peers, excluding self.
// In Hidden or Passive mode, returns an empty slice (no querying allowed).
// Returns an error if no signature has been set.
func (d *Discovery) FindSimilar(ctx context.Context, count int) ([]peer.AddrInfo, error) {
	d.mu.RLock()
	sig := d.signature
	visibility := d.visibility
	d.mu.RUnlock()

	// In hidden or passive mode, do not query DHT
	if visibility == VisibilityHidden || visibility == VisibilityPassive {
		return []peer.AddrInfo{}, nil
	}

	if sig == nil {
		return nil, errors.New("no signature set")
	}

	// Extract buckets from signature
	buckets := ExtractBuckets(sig.Signature, d.bucketSize)

	// Track seen peers for deduplication
	seen := make(map[peer.ID]peer.AddrInfo)
	selfID := d.host.ID()

	// Query each bucket for providers
	for prefix, value := range buckets {
		key := BucketToDHTKey(prefix, value)
		providers, err := d.dht.FindProviders(ctx, key, count)
		if err != nil {
			// Report error via callback but continue with other buckets
			d.mu.RLock()
			onError := d.onError
			d.mu.RUnlock()
			if onError != nil {
				onError(fmt.Errorf("FindProviders failed for bucket %d (key: %s): %w", prefix, key, err))
			}
			continue
		}

		for _, p := range providers {
			// Skip self
			if p.ID == selfID {
				continue
			}
			// Deduplicate
			if _, exists := seen[p.ID]; !exists {
				seen[p.ID] = p
			}
		}

		// Stop early if we have enough peers
		if len(seen) >= count {
			break
		}
	}

	// Convert map to slice
	result := make([]peer.AddrInfo, 0, len(seen))
	for _, p := range seen {
		result = append(result, p)
		if len(result) >= count {
			break
		}
	}

	return result, nil
}

// ExtractBuckets divides an LSH signature into buckets of the specified bit size.
// Each bucket is a segment of consecutive bits from the signature, represented
// as an unsigned integer value.
//
// For example, with bucketSize=4 and a 16-bit signature:
//   - Bucket 0: bits 0-3
//   - Bucket 1: bits 4-7
//   - Bucket 2: bits 8-11
//   - Bucket 3: bits 12-15
//
// The last bucket may have fewer bits if the signature size is not evenly divisible.
func ExtractBuckets(sig lsh.Signature, bucketSize int) []uint64 {
	if sig.Size == 0 || bucketSize <= 0 {
		return []uint64{}
	}

	numBuckets := (sig.Size + bucketSize - 1) / bucketSize // ceiling division
	buckets := make([]uint64, numBuckets)

	for i := 0; i < numBuckets; i++ {
		var value uint64
		startBit := i * bucketSize
		endBit := startBit + bucketSize
		if endBit > sig.Size {
			endBit = sig.Size
		}

		for j := startBit; j < endBit; j++ {
			if sig.GetBit(j) {
				// Set bit at position (j - startBit) within this bucket
				value |= 1 << uint(j-startBit)
			}
		}

		buckets[i] = value
	}

	return buckets
}

// BucketToDHTKey generates a DHT key for an LSH bucket.
// The key format is: /mymonad/lsh/<bucket-prefix>/<bucket-value>
// This allows peers with similar signature buckets to find each other.
func BucketToDHTKey(bucketPrefix int, bucketValue uint64) string {
	return fmt.Sprintf("/mymonad/lsh/%d/%d", bucketPrefix, bucketValue)
}

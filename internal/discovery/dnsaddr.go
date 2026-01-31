// Package discovery provides peer discovery mechanisms for the P2P network.
// It implements multiple discovery methods including DNSADDR bootstrap resolution.
package discovery

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/multiformats/go-multiaddr"
)

const (
	// dnsaddrPrefix is the standard prefix for DNSADDR TXT records.
	dnsaddrPrefix = "dnsaddr="

	// defaultTimeout is the default timeout for DNS resolution.
	defaultTimeout = 10 * time.Second
)

var (
	// ErrInvalidDNSADDR is returned when a DNSADDR record is malformed.
	ErrInvalidDNSADDR = errors.New("discovery: invalid DNSADDR record")

	// ErrNoRecords is returned when no valid DNSADDR records are found.
	ErrNoRecords = errors.New("discovery: no DNSADDR records found")
)

// txtResolver interface allows for dependency injection in tests.
type txtResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// DNSADDRResolver resolves DNSADDR TXT records to peer multiaddrs.
// It supports parallel resolution of multiple DNS seeds and shuffles
// results to distribute load across bootstrap nodes.
type DNSADDRResolver struct {
	timeout  time.Duration
	resolver txtResolver
}

// NewDNSADDRResolver creates a new DNSADDR resolver with the specified timeout.
// If timeout is 0, a default of 10 seconds is used.
func NewDNSADDRResolver(timeout time.Duration) *DNSADDRResolver {
	if timeout == 0 {
		timeout = defaultTimeout
	}
	return &DNSADDRResolver{
		timeout:  timeout,
		resolver: net.DefaultResolver,
	}
}

// ParseDNSADDR parses a single DNSADDR TXT record and returns a multiaddr.
// The record format is: dnsaddr=/dns4/host/tcp/port/p2p/peerID
// Returns ErrInvalidDNSADDR if the record is malformed.
func ParseDNSADDR(record string) (multiaddr.Multiaddr, error) {
	// Trim whitespace
	record = strings.TrimSpace(record)

	// Check for empty record
	if record == "" {
		return nil, ErrInvalidDNSADDR
	}

	// Must start with dnsaddr=
	if !strings.HasPrefix(record, dnsaddrPrefix) {
		return nil, ErrInvalidDNSADDR
	}

	// Extract the multiaddr string
	maStr := strings.TrimPrefix(record, dnsaddrPrefix)
	if maStr == "" {
		return nil, ErrInvalidDNSADDR
	}

	// Parse as multiaddr
	ma, err := multiaddr.NewMultiaddr(maStr)
	if err != nil {
		return nil, ErrInvalidDNSADDR
	}

	return ma, nil
}

// parseRecords extracts valid multiaddrs from a slice of TXT records.
// Invalid records are silently skipped.
func parseRecords(records []string) []multiaddr.Multiaddr {
	addrs := make([]multiaddr.Multiaddr, 0, len(records))

	for _, record := range records {
		ma, err := ParseDNSADDR(record)
		if err != nil {
			continue // Skip invalid records
		}
		addrs = append(addrs, ma)
	}

	return addrs
}

// Resolve queries DNS TXT records for the given domain and returns peer multiaddrs.
// The dnsaddr parameter should be the full DNS name including _dnsaddr prefix
// (e.g., "_dnsaddr.bootstrap.example.com").
// Returns ErrNoRecords if no valid DNSADDR records are found.
func (r *DNSADDRResolver) Resolve(ctx context.Context, dnsaddr string) ([]multiaddr.Multiaddr, error) {
	// Validate input
	if dnsaddr == "" {
		return nil, ErrInvalidDNSADDR
	}

	// Create context with timeout
	resolveCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Perform DNS TXT lookup
	records, err := r.resolver.LookupTXT(resolveCtx, dnsaddr)
	if err != nil {
		return nil, err
	}

	// Parse records
	addrs := parseRecords(records)

	if len(addrs) == 0 {
		return nil, ErrNoRecords
	}

	return addrs, nil
}

// ResolveMultiple resolves multiple DNS seeds in parallel and combines results.
// Failed resolutions are silently ignored - the function returns all successfully
// resolved addresses. Results are shuffled to distribute load across nodes.
// Duplicate addresses are removed.
func (r *DNSADDRResolver) ResolveMultiple(ctx context.Context, seeds []string) []multiaddr.Multiaddr {
	if len(seeds) == 0 {
		return []multiaddr.Multiaddr{}
	}

	// Channel to collect results
	type result struct {
		addrs []multiaddr.Multiaddr
	}
	results := make(chan result, len(seeds))

	// Launch parallel resolution
	var wg sync.WaitGroup
	for _, seed := range seeds {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()

			addrs, err := r.Resolve(ctx, s)
			if err != nil {
				// Send empty result on error
				results <- result{addrs: nil}
				return
			}
			results <- result{addrs: addrs}
		}(seed)
	}

	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and deduplicate results
	seen := make(map[string]bool)
	var combined []multiaddr.Multiaddr

	for res := range results {
		for _, addr := range res.addrs {
			key := addr.String()
			if !seen[key] {
				seen[key] = true
				combined = append(combined, addr)
			}
		}
	}

	// Shuffle to distribute load
	shuffleAddrs(combined)

	return combined
}

// shuffleAddrs randomly shuffles a slice of multiaddrs in place.
// This helps distribute connection attempts across bootstrap nodes.
func shuffleAddrs(addrs []multiaddr.Multiaddr) {
	if len(addrs) <= 1 {
		return
	}

	// Use a local random source for thread safety
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	rng.Shuffle(len(addrs), func(i, j int) {
		addrs[i], addrs[j] = addrs[j], addrs[i]
	})
}

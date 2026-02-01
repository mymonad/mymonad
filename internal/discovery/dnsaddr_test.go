// Package discovery provides peer discovery mechanisms for the P2P network.
package discovery

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/multiformats/go-multiaddr"
)

// ============================================================
// ParseDNSADDR Tests
// ============================================================

func TestParseDNSADDRValid(t *testing.T) {
	testCases := []struct {
		name     string
		record   string
		expected string
	}{
		{
			name:     "dns4 with tcp and p2p",
			record:   "dnsaddr=/dns4/bootstrap.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
			expected: "/dns4/bootstrap.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
		},
		{
			name:     "dns6 with tcp and p2p",
			record:   "dnsaddr=/dns6/ipv6.bootstrap.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
			expected: "/dns6/ipv6.bootstrap.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
		},
		{
			name:     "dns with udp and quic",
			record:   "dnsaddr=/dns/relay.example.com/udp/4001/quic-v1/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
			expected: "/dns/relay.example.com/udp/4001/quic-v1/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
		},
		{
			name:     "with webtransport",
			record:   "dnsaddr=/dns4/wt.example.com/udp/443/quic-v1/webtransport/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
			expected: "/dns4/wt.example.com/udp/443/quic-v1/webtransport/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ma, err := ParseDNSADDR(tc.record)
			if err != nil {
				t.Fatalf("ParseDNSADDR(%q) returned error: %v", tc.record, err)
			}
			if ma.String() != tc.expected {
				t.Errorf("ParseDNSADDR(%q) = %q, want %q", tc.record, ma.String(), tc.expected)
			}
		})
	}
}

func TestParseDNSADDRInvalid(t *testing.T) {
	testCases := []struct {
		name   string
		record string
	}{
		{
			name:   "empty record",
			record: "",
		},
		{
			name:   "missing dnsaddr prefix",
			record: "/dns4/bootstrap.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
		},
		{
			name:   "wrong prefix",
			record: "dnssrv=/dns4/bootstrap.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
		},
		{
			name:   "only prefix",
			record: "dnsaddr=",
		},
		{
			name:   "prefix without equals",
			record: "dnsaddr/dns4/bootstrap.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
		},
		{
			name:   "invalid multiaddr",
			record: "dnsaddr=/invalid/multiaddr",
		},
		{
			name:   "whitespace only",
			record: "   ",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ma, err := ParseDNSADDR(tc.record)
			if err == nil {
				t.Errorf("ParseDNSADDR(%q) should return error, got %v", tc.record, ma)
			}
			if err != nil && err != ErrInvalidDNSADDR {
				t.Errorf("ParseDNSADDR(%q) should return ErrInvalidDNSADDR, got %v", tc.record, err)
			}
		})
	}
}

// ============================================================
// parseRecords Tests (helper function)
// ============================================================

func TestParseRecordsAllValid(t *testing.T) {
	records := []string{
		"dnsaddr=/dns4/node1.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
		"dnsaddr=/dns4/node2.example.com/tcp/4001/p2p/12D3KooWHsF2rqmFNSqNfaLJYcBzKVVj9HGqGu7MCRwSNLZmBBXn",
	}

	addrs := parseRecords(records)

	if len(addrs) != 2 {
		t.Fatalf("parseRecords returned %d addrs, want 2", len(addrs))
	}

	// Verify each address is valid
	for i, addr := range addrs {
		if addr == nil {
			t.Errorf("parseRecords returned nil addr at index %d", i)
		}
	}
}

func TestParseRecordsMixedValidInvalid(t *testing.T) {
	records := []string{
		"dnsaddr=/dns4/node1.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
		"invalid record",
		"dnsaddr=/dns4/node2.example.com/tcp/4001/p2p/12D3KooWHsF2rqmFNSqNfaLJYcBzKVVj9HGqGu7MCRwSNLZmBBXn",
		"another invalid",
		"dnsaddr=/dns4/node3.example.com/tcp/4001/p2p/12D3KooWQcLUVxNjhLpjQERRQ9H3hLvKCgK9zcDqKxNMuKqJWUjE",
	}

	addrs := parseRecords(records)

	if len(addrs) != 3 {
		t.Fatalf("parseRecords should extract 3 valid addrs, got %d", len(addrs))
	}
}

func TestParseRecordsAllInvalid(t *testing.T) {
	records := []string{
		"invalid record",
		"another invalid",
		"not a dnsaddr",
	}

	addrs := parseRecords(records)

	if len(addrs) != 0 {
		t.Errorf("parseRecords should return empty for all invalid records, got %d", len(addrs))
	}
}

func TestParseRecordsEmpty(t *testing.T) {
	records := []string{}

	addrs := parseRecords(records)

	if len(addrs) != 0 {
		t.Errorf("parseRecords should return empty for empty input, got %d", len(addrs))
	}
}

func TestParseRecordsWithWhitespace(t *testing.T) {
	records := []string{
		"  dnsaddr=/dns4/node1.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM  ",
		"\tdnsaddr=/dns4/node2.example.com/tcp/4001/p2p/12D3KooWHsF2rqmFNSqNfaLJYcBzKVVj9HGqGu7MCRwSNLZmBBXn\t",
	}

	addrs := parseRecords(records)

	if len(addrs) != 2 {
		t.Fatalf("parseRecords should handle whitespace, got %d addrs", len(addrs))
	}
}

// ============================================================
// DNSADDRResolver Constructor Tests
// ============================================================

func TestNewDNSADDRResolver(t *testing.T) {
	r := NewDNSADDRResolver(5 * time.Second)
	if r == nil {
		t.Fatal("NewDNSADDRResolver returned nil")
	}
	if r.timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", r.timeout)
	}
}

func TestNewDNSADDRResolverDefaultTimeout(t *testing.T) {
	r := NewDNSADDRResolver(0)
	if r == nil {
		t.Fatal("NewDNSADDRResolver returned nil")
	}
	// Zero timeout should default to 10 seconds
	if r.timeout != 10*time.Second {
		t.Errorf("timeout = %v, want 10s (default)", r.timeout)
	}
}

// ============================================================
// ResolveMultiple Tests
// ============================================================

func TestResolveMultipleEmpty(t *testing.T) {
	r := NewDNSADDRResolver(5 * time.Second)
	ctx := context.Background()

	addrs := r.ResolveMultiple(ctx, []string{})

	if len(addrs) != 0 {
		t.Errorf("ResolveMultiple with empty seeds should return empty, got %d", len(addrs))
	}
}

func TestResolveMultipleContextCancelled(t *testing.T) {
	r := NewDNSADDRResolver(5 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	seeds := []string{
		"_dnsaddr.bootstrap.example.com",
		"_dnsaddr.seed.example.com",
	}

	// Should return empty or partial results when context is cancelled
	addrs := r.ResolveMultiple(ctx, seeds)

	// This is expected to return empty because context is cancelled
	// The key is it should not hang or panic
	_ = addrs
}

// ============================================================
// shuffleAddrs Tests
// ============================================================

func TestShuffleAddrs(t *testing.T) {
	// Create test addresses
	testAddrs := []string{
		"/dns4/node1.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
		"/dns4/node2.example.com/tcp/4001/p2p/12D3KooWHsF2rqmFNSqNfaLJYcBzKVVj9HGqGu7MCRwSNLZmBBXn",
		"/dns4/node3.example.com/tcp/4001/p2p/12D3KooWQcLUVxNjhLpjQERRQ9H3hLvKCgK9zcDqKxNMuKqJWUjE",
		"/dns4/node4.example.com/tcp/4001/p2p/12D3KooWRYhPxzNt4bfJ3d5cRBBPCW6EJwZWWfnNkGqvL9yMQBVE",
		"/dns4/node5.example.com/tcp/4001/p2p/12D3KooWKW4CbJPXKqJC9bzU2MHqUUXTEJvMxPTX7B5dhM5zSLVB",
	}

	addrs := make([]multiaddr.Multiaddr, 0, len(testAddrs))
	for _, s := range testAddrs {
		ma, _ := multiaddr.NewMultiaddr(s)
		addrs = append(addrs, ma)
	}

	// Make a copy to compare
	original := make([]string, len(addrs))
	for i, a := range addrs {
		original[i] = a.String()
	}

	// Shuffle
	shuffleAddrs(addrs)

	// Verify same length
	if len(addrs) != len(original) {
		t.Errorf("shuffleAddrs changed length: got %d, want %d", len(addrs), len(original))
	}

	// Verify all elements are still present
	shuffled := make(map[string]bool)
	for _, a := range addrs {
		shuffled[a.String()] = true
	}

	for _, o := range original {
		if !shuffled[o] {
			t.Errorf("shuffleAddrs lost element: %s", o)
		}
	}
}

func TestShuffleAddrsEmpty(t *testing.T) {
	addrs := []multiaddr.Multiaddr{}
	shuffleAddrs(addrs) // Should not panic
}

func TestShuffleAddrsSingleElement(t *testing.T) {
	ma, _ := multiaddr.NewMultiaddr("/dns4/node1.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM")
	addrs := []multiaddr.Multiaddr{ma}

	shuffleAddrs(addrs)

	if len(addrs) != 1 {
		t.Errorf("shuffleAddrs with single element should keep 1 element, got %d", len(addrs))
	}
}

// ============================================================
// Resolve Tests (using mock resolver for unit tests)
// ============================================================

// mockResolver allows testing without real DNS queries
type mockResolver struct {
	records map[string][]string
	err     error
}

func (m *mockResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.records[name], nil
}

func TestResolveWithMockSuccess(t *testing.T) {
	r := NewDNSADDRResolver(5 * time.Second)
	r.resolver = &mockResolver{
		records: map[string][]string{
			"_dnsaddr.bootstrap.example.com": {
				"dnsaddr=/dns4/node1.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
				"dnsaddr=/dns4/node2.example.com/tcp/4001/p2p/12D3KooWHsF2rqmFNSqNfaLJYcBzKVVj9HGqGu7MCRwSNLZmBBXn",
			},
		},
	}

	ctx := context.Background()
	addrs, err := r.Resolve(ctx, "_dnsaddr.bootstrap.example.com")

	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	if len(addrs) != 2 {
		t.Fatalf("Resolve returned %d addrs, want 2", len(addrs))
	}
}

func TestResolveWithMockNoRecords(t *testing.T) {
	r := NewDNSADDRResolver(5 * time.Second)
	r.resolver = &mockResolver{
		records: map[string][]string{
			"_dnsaddr.bootstrap.example.com": {},
		},
	}

	ctx := context.Background()
	_, err := r.Resolve(ctx, "_dnsaddr.bootstrap.example.com")

	if err != ErrNoRecords {
		t.Errorf("Resolve should return ErrNoRecords for empty records, got %v", err)
	}
}

func TestResolveWithMockMixedRecords(t *testing.T) {
	r := NewDNSADDRResolver(5 * time.Second)
	r.resolver = &mockResolver{
		records: map[string][]string{
			"_dnsaddr.bootstrap.example.com": {
				"dnsaddr=/dns4/node1.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
				"v=spf1 include:_spf.example.com ~all", // Non-DNSADDR record
				"invalid dnsaddr",
				"dnsaddr=/dns4/node2.example.com/tcp/4001/p2p/12D3KooWHsF2rqmFNSqNfaLJYcBzKVVj9HGqGu7MCRwSNLZmBBXn",
			},
		},
	}

	ctx := context.Background()
	addrs, err := r.Resolve(ctx, "_dnsaddr.bootstrap.example.com")

	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	if len(addrs) != 2 {
		t.Fatalf("Resolve should return 2 valid addrs from mixed records, got %d", len(addrs))
	}
}

func TestResolveWithMockDNSError(t *testing.T) {
	r := NewDNSADDRResolver(5 * time.Second)
	r.resolver = &mockResolver{
		err: &mockDNSError{isTemporary: true},
	}

	ctx := context.Background()
	_, err := r.Resolve(ctx, "_dnsaddr.bootstrap.example.com")

	if err == nil {
		t.Error("Resolve should return error when DNS lookup fails")
	}
}

type mockDNSError struct {
	isTemporary bool
}

func (e *mockDNSError) Error() string   { return "mock dns error" }
func (e *mockDNSError) Timeout() bool   { return e.isTemporary }
func (e *mockDNSError) Temporary() bool { return e.isTemporary }

// ============================================================
// ResolveMultiple with Mock Tests
// ============================================================

func TestResolveMultipleWithMock(t *testing.T) {
	r := NewDNSADDRResolver(5 * time.Second)
	r.resolver = &mockResolver{
		records: map[string][]string{
			"_dnsaddr.seed1.example.com": {
				"dnsaddr=/dns4/node1.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
			},
			"_dnsaddr.seed2.example.com": {
				"dnsaddr=/dns4/node2.example.com/tcp/4001/p2p/12D3KooWHsF2rqmFNSqNfaLJYcBzKVVj9HGqGu7MCRwSNLZmBBXn",
			},
			"_dnsaddr.seed3.example.com": {
				"dnsaddr=/dns4/node3.example.com/tcp/4001/p2p/12D3KooWQcLUVxNjhLpjQERRQ9H3hLvKCgK9zcDqKxNMuKqJWUjE",
			},
		},
	}

	ctx := context.Background()
	seeds := []string{
		"_dnsaddr.seed1.example.com",
		"_dnsaddr.seed2.example.com",
		"_dnsaddr.seed3.example.com",
	}

	addrs := r.ResolveMultiple(ctx, seeds)

	if len(addrs) != 3 {
		t.Fatalf("ResolveMultiple should return 3 addrs, got %d", len(addrs))
	}
}

func TestResolveMultipleWithPartialFailures(t *testing.T) {
	// Create a resolver that fails for one seed
	failingResolver := &selectiveFailResolver{
		records: map[string][]string{
			"_dnsaddr.seed1.example.com": {
				"dnsaddr=/dns4/node1.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
			},
			"_dnsaddr.seed3.example.com": {
				"dnsaddr=/dns4/node3.example.com/tcp/4001/p2p/12D3KooWQcLUVxNjhLpjQERRQ9H3hLvKCgK9zcDqKxNMuKqJWUjE",
			},
		},
		failOn: "_dnsaddr.seed2.example.com",
	}

	r := NewDNSADDRResolver(5 * time.Second)
	r.resolver = failingResolver

	ctx := context.Background()
	seeds := []string{
		"_dnsaddr.seed1.example.com",
		"_dnsaddr.seed2.example.com", // This will fail
		"_dnsaddr.seed3.example.com",
	}

	addrs := r.ResolveMultiple(ctx, seeds)

	// Should still get 2 addrs from the seeds that succeeded
	if len(addrs) != 2 {
		t.Fatalf("ResolveMultiple should return 2 addrs with one failure, got %d", len(addrs))
	}
}

type selectiveFailResolver struct {
	records map[string][]string
	failOn  string
}

func (r *selectiveFailResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if name == r.failOn {
		return nil, &mockDNSError{isTemporary: true}
	}
	return r.records[name], nil
}

// ============================================================
// Parallel Resolution Tests
// ============================================================

func TestResolveMultipleParallel(t *testing.T) {
	// Track when lookups start to verify parallelism
	var mu sync.Mutex
	lookupTimes := make(map[string]time.Time)

	r := NewDNSADDRResolver(5 * time.Second)
	r.resolver = &timingResolver{
		records: map[string][]string{
			"_dnsaddr.seed1.example.com": {
				"dnsaddr=/dns4/node1.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
			},
			"_dnsaddr.seed2.example.com": {
				"dnsaddr=/dns4/node2.example.com/tcp/4001/p2p/12D3KooWHsF2rqmFNSqNfaLJYcBzKVVj9HGqGu7MCRwSNLZmBBXn",
			},
			"_dnsaddr.seed3.example.com": {
				"dnsaddr=/dns4/node3.example.com/tcp/4001/p2p/12D3KooWQcLUVxNjhLpjQERRQ9H3hLvKCgK9zcDqKxNMuKqJWUjE",
			},
		},
		delay:       50 * time.Millisecond,
		mu:          &mu,
		lookupTimes: lookupTimes,
	}

	ctx := context.Background()
	seeds := []string{
		"_dnsaddr.seed1.example.com",
		"_dnsaddr.seed2.example.com",
		"_dnsaddr.seed3.example.com",
	}

	start := time.Now()
	addrs := r.ResolveMultiple(ctx, seeds)
	elapsed := time.Since(start)

	if len(addrs) != 3 {
		t.Fatalf("ResolveMultiple should return 3 addrs, got %d", len(addrs))
	}

	// If run in parallel with 50ms delay each, should complete in ~50-100ms
	// If sequential, would take ~150ms+
	if elapsed > 130*time.Millisecond {
		t.Errorf("ResolveMultiple took %v, expected parallel execution (<130ms)", elapsed)
	}

	// Verify all lookups started within a short window (indicating parallelism)
	mu.Lock()
	defer mu.Unlock()

	var minTime, maxTime time.Time
	for _, lt := range lookupTimes {
		if minTime.IsZero() || lt.Before(minTime) {
			minTime = lt
		}
		if maxTime.IsZero() || lt.After(maxTime) {
			maxTime = lt
		}
	}

	// All lookups should start within 20ms of each other if parallel
	if maxTime.Sub(minTime) > 20*time.Millisecond {
		t.Errorf("Lookups started %v apart, expected parallel start (<20ms)", maxTime.Sub(minTime))
	}
}

type timingResolver struct {
	records     map[string][]string
	delay       time.Duration
	mu          *sync.Mutex
	lookupTimes map[string]time.Time
}

func (r *timingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	r.mu.Lock()
	r.lookupTimes[name] = time.Now()
	r.mu.Unlock()

	time.Sleep(r.delay)
	return r.records[name], nil
}

// ============================================================
// Edge Cases and Error Handling
// ============================================================

func TestResolveEmptyDNSAddr(t *testing.T) {
	r := NewDNSADDRResolver(5 * time.Second)
	ctx := context.Background()

	_, err := r.Resolve(ctx, "")

	if err == nil {
		t.Error("Resolve should return error for empty dnsaddr")
	}
}

func TestResolveInvalidDNSName(t *testing.T) {
	r := NewDNSADDRResolver(5 * time.Second)
	ctx := context.Background()

	// This should fail DNS lookup (using real resolver)
	// We're testing that the function handles errors gracefully
	_, err := r.Resolve(ctx, "_dnsaddr.this-domain-should-not-exist-example-test-12345.invalid")

	// Should get an error (either DNS error or no records)
	if err == nil {
		t.Error("Resolve should return error for non-existent domain")
	}
}

// ============================================================
// Deduplication Tests
// ============================================================

func TestResolveMultipleDeduplicates(t *testing.T) {
	r := NewDNSADDRResolver(5 * time.Second)
	r.resolver = &mockResolver{
		records: map[string][]string{
			"_dnsaddr.seed1.example.com": {
				"dnsaddr=/dns4/node1.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
				"dnsaddr=/dns4/node2.example.com/tcp/4001/p2p/12D3KooWHsF2rqmFNSqNfaLJYcBzKVVj9HGqGu7MCRwSNLZmBBXn",
			},
			"_dnsaddr.seed2.example.com": {
				// Same node1 as in seed1 - should be deduplicated
				"dnsaddr=/dns4/node1.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
				"dnsaddr=/dns4/node3.example.com/tcp/4001/p2p/12D3KooWQcLUVxNjhLpjQERRQ9H3hLvKCgK9zcDqKxNMuKqJWUjE",
			},
		},
	}

	ctx := context.Background()
	seeds := []string{
		"_dnsaddr.seed1.example.com",
		"_dnsaddr.seed2.example.com",
	}

	addrs := r.ResolveMultiple(ctx, seeds)

	// node1 appears in both seeds, should only appear once
	if len(addrs) != 3 {
		t.Fatalf("ResolveMultiple should deduplicate, expected 3 unique addrs, got %d", len(addrs))
	}

	// Verify no duplicates
	seen := make(map[string]bool)
	for _, addr := range addrs {
		s := addr.String()
		if seen[s] {
			t.Errorf("Duplicate address found: %s", s)
		}
		seen[s] = true
	}
}

// ============================================================
// Format Normalization Tests
// ============================================================

func TestParseDNSADDRNormalizesFormat(t *testing.T) {
	// Test that parsed multiaddr is properly normalized
	record := "dnsaddr=/dns4/bootstrap.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM"

	ma, err := ParseDNSADDR(record)
	if err != nil {
		t.Fatalf("ParseDNSADDR failed: %v", err)
	}

	// The multiaddr should be properly formatted
	s := ma.String()
	if !strings.HasPrefix(s, "/dns4/") {
		t.Errorf("Parsed multiaddr should start with /dns4/, got %s", s)
	}

	// Should contain all components
	if !strings.Contains(s, "/tcp/4001/") {
		t.Errorf("Parsed multiaddr should contain /tcp/4001/, got %s", s)
	}
	if !strings.Contains(s, "/p2p/") {
		t.Errorf("Parsed multiaddr should contain /p2p/, got %s", s)
	}
}

// Package discovery provides peer discovery mechanisms for the P2P network.
package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// ============================================================
// Test Multiaddrs (valid libp2p peer addresses)
// ============================================================

const (
	// Valid multiaddr strings with peer IDs for testing
	testPeer1Addr = "/ip4/192.168.1.1/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM"
	testPeer2Addr = "/ip4/192.168.1.2/tcp/4001/p2p/12D3KooWHsF2rqmFNSqNfaLJYcBzKVVj9HGqGu7MCRwSNLZmBBXn"
	testPeer3Addr = "/ip4/192.168.1.3/tcp/4001/p2p/12D3KooWQcLUVxNjhLpjQERRQ9H3hLvKCgK9zcDqKxNMuKqJWUjE"
	testPeer4Addr = "/ip4/192.168.1.4/tcp/4001/p2p/12D3KooWRYhPxzNt4bfJ3d5cRBBPCW6EJwZWWfnNkGqvL9yMQBVE"

	// DNS-based multiaddrs for DNSADDR resolution
	testDNSPeer1Addr = "/dns4/node1.example.com/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM"
	testDNSPeer2Addr = "/dns4/node2.example.com/tcp/4001/p2p/12D3KooWHsF2rqmFNSqNfaLJYcBzKVVj9HGqGu7MCRwSNLZmBBXn"
	testDNSPeer5Addr = "/dns4/node5.example.com/tcp/4001/p2p/12D3KooWKW4CbJPXKqJC9bzU2MHqUUXTEJvMxPTX7B5dhM5zSLVB"
)

// ============================================================
// NewManager Tests
// ============================================================

func TestNewManager(t *testing.T) {
	cfg := ManagerConfig{
		DNSSeeds:    []string{"_dnsaddr.bootstrap.example.com"},
		Bootstrap:   []string{testPeer1Addr},
		MDNSEnabled: true,
		DNSTimeout:  5 * time.Second,
	}

	m := NewManager(cfg)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}

	if m.config.MDNSEnabled != true {
		t.Errorf("MDNSEnabled = %v, want true", m.config.MDNSEnabled)
	}

	if m.resolver == nil {
		t.Error("NewManager should initialize resolver")
	}
}

func TestNewManagerDefaults(t *testing.T) {
	cfg := ManagerConfig{}
	m := NewManager(cfg)

	if m == nil {
		t.Fatal("NewManager returned nil")
	}

	if m.resolver == nil {
		t.Error("NewManager should initialize resolver with defaults")
	}
}

// ============================================================
// Config Accessor Tests
// ============================================================

func TestManagerConfig(t *testing.T) {
	cfg := ManagerConfig{
		DNSSeeds:    []string{"_dnsaddr.seed1.example.com", "_dnsaddr.seed2.example.com"},
		Bootstrap:   []string{testPeer1Addr, testPeer2Addr},
		MDNSEnabled: true,
		DNSTimeout:  15 * time.Second,
	}

	m := NewManager(cfg)
	returned := m.Config()

	if len(returned.DNSSeeds) != 2 {
		t.Errorf("Config().DNSSeeds length = %d, want 2", len(returned.DNSSeeds))
	}

	if len(returned.Bootstrap) != 2 {
		t.Errorf("Config().Bootstrap length = %d, want 2", len(returned.Bootstrap))
	}

	if returned.MDNSEnabled != true {
		t.Errorf("Config().MDNSEnabled = %v, want true", returned.MDNSEnabled)
	}

	if returned.DNSTimeout != 15*time.Second {
		t.Errorf("Config().DNSTimeout = %v, want 15s", returned.DNSTimeout)
	}
}

// ============================================================
// parseBootstrapAddrs Tests
// ============================================================

func TestParseBootstrapAddrsValid(t *testing.T) {
	m := NewManager(ManagerConfig{})

	addrs := []string{
		testPeer1Addr,
		testPeer2Addr,
	}

	peers := m.parseBootstrapAddrs(addrs)

	if len(peers) != 2 {
		t.Fatalf("parseBootstrapAddrs returned %d peers, want 2", len(peers))
	}

	// Verify each peer has an ID and addresses
	for i, p := range peers {
		if p.ID == "" {
			t.Errorf("peer[%d] has empty ID", i)
		}
		if len(p.Addrs) == 0 {
			t.Errorf("peer[%d] has no addresses", i)
		}
	}
}

func TestParseBootstrapAddrsInvalid(t *testing.T) {
	m := NewManager(ManagerConfig{})

	testCases := []struct {
		name  string
		addrs []string
		want  int // expected number of valid peers
	}{
		{
			name:  "empty slice",
			addrs: []string{},
			want:  0,
		},
		{
			name:  "all invalid",
			addrs: []string{"invalid", "also-invalid", "not-a-multiaddr"},
			want:  0,
		},
		{
			name: "multiaddr without peer ID",
			addrs: []string{
				"/ip4/192.168.1.1/tcp/4001", // Missing /p2p/ component
			},
			want: 0,
		},
		{
			name: "mixed valid and invalid",
			addrs: []string{
				testPeer1Addr, // valid
				"invalid",
				testPeer2Addr, // valid
				"/ip4/192.168.1.1/tcp/4001", // invalid - no peer ID
			},
			want: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			peers := m.parseBootstrapAddrs(tc.addrs)
			if len(peers) != tc.want {
				t.Errorf("parseBootstrapAddrs returned %d peers, want %d", len(peers), tc.want)
			}
		})
	}
}

func TestParseBootstrapAddrsDeduplicate(t *testing.T) {
	m := NewManager(ManagerConfig{})

	// Same peer ID with different addresses should be combined
	addrs := []string{
		"/ip4/192.168.1.1/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM",
		"/ip4/10.0.0.1/tcp/4001/p2p/12D3KooWGzBnkPqQNyFQDqNjqJHGSfLrpJLf8vGCvGxCmjL5ikPM", // Same peer ID
		testPeer2Addr,
	}

	peers := m.parseBootstrapAddrs(addrs)

	if len(peers) != 2 {
		t.Fatalf("parseBootstrapAddrs should deduplicate by peer ID, got %d peers, want 2", len(peers))
	}

	// The first peer should have multiple addresses
	var foundMultiAddr bool
	for _, p := range peers {
		if len(p.Addrs) > 1 {
			foundMultiAddr = true
			break
		}
	}

	if !foundMultiAddr {
		t.Error("parseBootstrapAddrs should combine addresses for same peer ID")
	}
}

// ============================================================
// DiscoverPeers Tests
// ============================================================

func TestDiscoverPeersEmpty(t *testing.T) {
	m := NewManager(ManagerConfig{})

	ctx := context.Background()
	peers := m.DiscoverPeers(ctx)

	if len(peers) != 0 {
		t.Errorf("DiscoverPeers with no sources should return empty, got %d", len(peers))
	}
}

func TestDiscoverPeersBootstrapOnly(t *testing.T) {
	cfg := ManagerConfig{
		Bootstrap: []string{testPeer1Addr, testPeer2Addr},
	}
	m := NewManager(cfg)

	ctx := context.Background()
	peers := m.DiscoverPeers(ctx)

	if len(peers) != 2 {
		t.Fatalf("DiscoverPeers should return 2 bootstrap peers, got %d", len(peers))
	}
}

func TestDiscoverPeersDNSOnly(t *testing.T) {
	cfg := ManagerConfig{
		DNSSeeds:   []string{"_dnsaddr.seed1.example.com"},
		DNSTimeout: 5 * time.Second,
	}
	m := NewManager(cfg)

	// Inject mock resolver
	m.resolver.resolver = &mockResolver{
		records: map[string][]string{
			"_dnsaddr.seed1.example.com": {
				"dnsaddr=" + testDNSPeer1Addr,
				"dnsaddr=" + testDNSPeer2Addr,
			},
		},
	}

	ctx := context.Background()
	peers := m.DiscoverPeers(ctx)

	if len(peers) != 2 {
		t.Fatalf("DiscoverPeers should return 2 DNS peers, got %d", len(peers))
	}
}

func TestDiscoverPeersPriorityOrder(t *testing.T) {
	// Bootstrap peers should come first, then DNSADDR peers
	cfg := ManagerConfig{
		Bootstrap:  []string{testPeer3Addr, testPeer4Addr},
		DNSSeeds:   []string{"_dnsaddr.seed1.example.com"},
		DNSTimeout: 5 * time.Second,
	}
	m := NewManager(cfg)

	// Inject mock resolver for DNS
	m.resolver.resolver = &mockResolver{
		records: map[string][]string{
			"_dnsaddr.seed1.example.com": {
				"dnsaddr=" + testDNSPeer1Addr,
				"dnsaddr=" + testDNSPeer2Addr,
			},
		},
	}

	ctx := context.Background()
	peers := m.DiscoverPeers(ctx)

	if len(peers) != 4 {
		t.Fatalf("DiscoverPeers should return 4 total peers, got %d", len(peers))
	}

	// Extract peer IDs for comparison
	peer3Info := mustParseAddrInfo(t, testPeer3Addr)
	peer4Info := mustParseAddrInfo(t, testPeer4Addr)

	// Bootstrap peers (peer3, peer4) should be at indices 0 and 1
	// (user-defined bootstrap has highest priority)
	bootstrapPeerIDs := make(map[peer.ID]bool)
	bootstrapPeerIDs[peer3Info.ID] = true
	bootstrapPeerIDs[peer4Info.ID] = true

	if !bootstrapPeerIDs[peers[0].ID] || !bootstrapPeerIDs[peers[1].ID] {
		t.Error("Bootstrap peers should appear first in DiscoverPeers result")
	}
}

func TestDiscoverPeersDeduplicatesByPeerID(t *testing.T) {
	// If bootstrap and DNSADDR return same peer ID, should be deduplicated
	cfg := ManagerConfig{
		Bootstrap: []string{testPeer1Addr}, // Uses peer ID 12D3KooWGz...
		DNSSeeds:  []string{"_dnsaddr.seed1.example.com"},
	}
	m := NewManager(cfg)

	// DNS returns same peer ID as bootstrap
	m.resolver.resolver = &mockResolver{
		records: map[string][]string{
			"_dnsaddr.seed1.example.com": {
				"dnsaddr=" + testDNSPeer1Addr, // Same peer ID as testPeer1Addr
				"dnsaddr=" + testDNSPeer5Addr, // Different peer ID
			},
		},
	}

	ctx := context.Background()
	peers := m.DiscoverPeers(ctx)

	// Should have only 2 unique peers (testPeer1 deduplicated, testDNSPeer5 unique)
	if len(peers) != 2 {
		t.Fatalf("DiscoverPeers should deduplicate by peer ID, got %d peers, want 2", len(peers))
	}
}

func TestDiscoverPeersContextCancelled(t *testing.T) {
	cfg := ManagerConfig{
		Bootstrap: []string{testPeer1Addr},
		DNSSeeds:  []string{"_dnsaddr.seed1.example.com"},
	}
	m := NewManager(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Should still return bootstrap peers (they don't require network)
	// DNS resolution may fail or be skipped
	peers := m.DiscoverPeers(ctx)

	// Should at minimum get bootstrap peers
	if len(peers) < 1 {
		t.Error("DiscoverPeers should return bootstrap peers even with cancelled context")
	}
}

func TestDiscoverPeersDNSFailure(t *testing.T) {
	cfg := ManagerConfig{
		Bootstrap: []string{testPeer1Addr},
		DNSSeeds:  []string{"_dnsaddr.seed1.example.com"},
	}
	m := NewManager(cfg)

	// Inject failing mock resolver
	m.resolver.resolver = &mockResolver{
		err: &mockDNSError{isTemporary: true},
	}

	ctx := context.Background()
	peers := m.DiscoverPeers(ctx)

	// Should still get bootstrap peer even if DNS fails
	if len(peers) != 1 {
		t.Fatalf("DiscoverPeers should return bootstrap peer even if DNS fails, got %d", len(peers))
	}
}

func TestDiscoverPeersMultipleDNSSeeds(t *testing.T) {
	cfg := ManagerConfig{
		DNSSeeds: []string{
			"_dnsaddr.seed1.example.com",
			"_dnsaddr.seed2.example.com",
		},
	}
	m := NewManager(cfg)

	m.resolver.resolver = &mockResolver{
		records: map[string][]string{
			"_dnsaddr.seed1.example.com": {
				"dnsaddr=" + testDNSPeer1Addr,
			},
			"_dnsaddr.seed2.example.com": {
				"dnsaddr=" + testDNSPeer2Addr,
			},
		},
	}

	ctx := context.Background()
	peers := m.DiscoverPeers(ctx)

	if len(peers) != 2 {
		t.Fatalf("DiscoverPeers should return peers from all DNS seeds, got %d", len(peers))
	}
}

// ============================================================
// Helper Functions
// ============================================================

func mustParseAddrInfo(t *testing.T, addr string) peer.AddrInfo {
	t.Helper()

	ma, err := multiaddr.NewMultiaddr(addr)
	if err != nil {
		t.Fatalf("failed to parse multiaddr %q: %v", addr, err)
	}

	info, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		t.Fatalf("failed to extract peer info from %q: %v", addr, err)
	}

	return *info
}

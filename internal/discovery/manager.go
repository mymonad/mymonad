// Package discovery provides peer discovery mechanisms for the P2P network.
// The Manager coordinates multiple discovery sources including user-defined
// bootstrap nodes, DNSADDR seeds, and mDNS (when enabled).
package discovery

import (
	"context"
	"log/slog"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// ManagerConfig holds configuration for the discovery Manager.
type ManagerConfig struct {
	// DNSSeeds are DNSADDR DNS names to resolve for peer discovery.
	// Example: "_dnsaddr.bootstrap.mymonad.network"
	DNSSeeds []string

	// Bootstrap are user-defined multiaddr strings for direct peer connections.
	// These have the highest priority and are tried first.
	Bootstrap []string

	// MDNSEnabled indicates whether mDNS local discovery is enabled.
	// Note: mDNS is handled separately by libp2p, this is for configuration tracking.
	MDNSEnabled bool

	// DNSTimeout is the timeout for DNS resolution operations.
	// If zero, a default of 10 seconds is used.
	DNSTimeout time.Duration
}

// Manager coordinates multiple peer discovery sources.
// It provides a unified interface to discover peers from:
// 1. User-defined bootstrap addresses (highest priority)
// 2. DNSADDR DNS seeds (community trust)
// 3. mDNS for local network discovery (handled separately)
// 4. DHT peer exchange (handled by libp2p separately)
type Manager struct {
	config   ManagerConfig
	resolver *DNSADDRResolver
	logger   *slog.Logger
}

// NewManager creates a new discovery Manager with the given configuration.
func NewManager(cfg ManagerConfig) *Manager {
	return NewManagerWithLogger(cfg, slog.Default())
}

// NewManagerWithLogger creates a new discovery Manager with the given configuration and logger.
func NewManagerWithLogger(cfg ManagerConfig, logger *slog.Logger) *Manager {
	timeout := cfg.DNSTimeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	return &Manager{
		config:   cfg,
		resolver: NewDNSADDRResolverWithLogger(timeout, logger),
		logger:   logger,
	}
}

// Config returns the manager's configuration.
func (m *Manager) Config() ManagerConfig {
	return m.config
}

// DiscoverPeers returns peers from all configured sources.
// Priority order: user bootstrap (first) > DNSADDR seeds.
// mDNS and DHT peer exchange are handled separately by libp2p.
// Peers are deduplicated by peer ID, with earlier sources taking precedence.
func (m *Manager) DiscoverPeers(ctx context.Context) []peer.AddrInfo {
	// Track seen peer IDs for deduplication
	seen := make(map[peer.ID]int) // Maps peer ID to index in result slice
	var result []peer.AddrInfo

	// 1. User-defined bootstrap addresses (highest priority)
	bootstrapPeers := m.parseBootstrapAddrs(m.config.Bootstrap)
	for _, p := range bootstrapPeers {
		if idx, exists := seen[p.ID]; exists {
			// Merge addresses for existing peer
			result[idx].Addrs = append(result[idx].Addrs, p.Addrs...)
		} else {
			seen[p.ID] = len(result)
			result = append(result, p)
		}
	}

	// 2. DNSADDR seeds (community trust)
	if len(m.config.DNSSeeds) > 0 {
		dnsAddrs := m.resolver.ResolveMultiple(ctx, m.config.DNSSeeds)
		dnsPeers := m.multiaddrsToAddrInfos(dnsAddrs)

		for _, p := range dnsPeers {
			if idx, exists := seen[p.ID]; exists {
				// Merge addresses for existing peer
				result[idx].Addrs = append(result[idx].Addrs, p.Addrs...)
			} else {
				seen[p.ID] = len(result)
				result = append(result, p)
			}
		}
	}

	return result
}

// parseBootstrapAddrs converts multiaddr strings to peer.AddrInfo slices.
// Invalid multiaddrs are silently skipped.
// Peers with the same ID are combined with their addresses merged.
func (m *Manager) parseBootstrapAddrs(addrs []string) []peer.AddrInfo {
	if len(addrs) == 0 {
		return nil
	}

	seen := make(map[peer.ID]int) // Maps peer ID to index in result slice
	var result []peer.AddrInfo

	for _, addrStr := range addrs {
		// Parse multiaddr string
		ma, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			m.logger.Warn("skipping invalid bootstrap multiaddr",
				"addr", addrStr,
				"error", err,
			)
			continue
		}

		// Extract peer info from multiaddr
		info, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			m.logger.Warn("skipping bootstrap multiaddr without peer ID",
				"addr", addrStr,
				"error", err,
			)
			continue
		}

		// Deduplicate by peer ID, merging addresses
		if idx, exists := seen[info.ID]; exists {
			result[idx].Addrs = append(result[idx].Addrs, info.Addrs...)
		} else {
			seen[info.ID] = len(result)
			result = append(result, *info)
		}
	}

	return result
}

// multiaddrsToAddrInfos converts a slice of multiaddrs to peer.AddrInfo slices.
// Multiaddrs without peer IDs are skipped.
// Peers with the same ID are combined with their addresses merged.
func (m *Manager) multiaddrsToAddrInfos(addrs []multiaddr.Multiaddr) []peer.AddrInfo {
	if len(addrs) == 0 {
		return nil
	}

	seen := make(map[peer.ID]int)
	var result []peer.AddrInfo

	for _, ma := range addrs {
		info, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			continue
		}

		if idx, exists := seen[info.ID]; exists {
			result[idx].Addrs = append(result[idx].Addrs, info.Addrs...)
		} else {
			seen[info.ID] = len(result)
			result = append(result, *info)
		}
	}

	return result
}

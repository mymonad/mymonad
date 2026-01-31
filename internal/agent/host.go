package agent

import (
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// Host wraps a libp2p host.
type Host struct {
	h host.Host
}

// NewHost creates a new libp2p host.
// If port is 0, a random available port is used.
// The ctx parameter is reserved for future use (libp2p options may accept context).
func NewHost(ctx context.Context, port int) (*Host, error) {
	_ = ctx // reserved for future use with libp2p options
	addr := fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port)

	h, err := libp2p.New(
		libp2p.ListenAddrStrings(addr),
		libp2p.DisableRelay(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	return &Host{h: h}, nil
}

// ID returns the peer ID.
func (h *Host) ID() peer.ID {
	return h.h.ID()
}

// Addrs returns the listen addresses.
func (h *Host) Addrs() []multiaddr.Multiaddr {
	return h.h.Addrs()
}

// AddrInfo returns the peer.AddrInfo for this host.
func (h *Host) AddrInfo() peer.AddrInfo {
	return peer.AddrInfo{
		ID:    h.h.ID(),
		Addrs: h.h.Addrs(),
	}
}

// Connect connects to another peer.
func (h *Host) Connect(ctx context.Context, pi peer.AddrInfo) error {
	if pi.ID == "" {
		return fmt.Errorf("peer ID cannot be empty")
	}
	if len(pi.Addrs) == 0 {
		return fmt.Errorf("peer must have at least one address")
	}
	return h.h.Connect(ctx, pi)
}

// Peers returns connected peer IDs.
func (h *Host) Peers() []peer.ID {
	return h.h.Network().Peers()
}

// Close shuts down the host.
func (h *Host) Close() error {
	return h.h.Close()
}

// Host returns the underlying libp2p host.
func (h *Host) Host() host.Host {
	return h.h
}

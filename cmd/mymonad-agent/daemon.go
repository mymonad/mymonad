package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	pb "github.com/mymonad/mymonad/api/proto"
	"github.com/mymonad/mymonad/internal/agent"
	"github.com/mymonad/mymonad/internal/config"
	"github.com/mymonad/mymonad/internal/crypto"
	"github.com/mymonad/mymonad/internal/discovery"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/grpc"
)

// Daemon states
const (
	StateIdle        = "idle"
	StateDiscovering = "discovering"
	StateConnecting  = "connecting"
	StateActive      = "active"
	StateError       = "error"
)

// Default identity passphrase - in production this should be user-provided
const defaultIdentityPassphrase = "mymonad-agent-identity"

// DaemonConfig holds configuration for the agent daemon.
type DaemonConfig struct {
	SocketPath          string
	IdentityPath        string
	Port                int
	DNSSeeds            []string
	Bootstrap           []string
	MDNSEnabled         bool
	SimilarityThreshold float64
	ChallengeDifficulty int
	IngestSocket        string // To fetch Monad from ingest daemon
}

// Validate checks that all required configuration fields are set.
func (c *DaemonConfig) Validate() error {
	if c.SocketPath == "" {
		return errors.New("socket path is required")
	}
	if c.IdentityPath == "" {
		return errors.New("identity path is required")
	}
	// Port 0 is valid (random port selection)
	if c.Port < 0 || c.Port > 65535 {
		return errors.New("port must be between 0 and 65535")
	}
	if c.SimilarityThreshold < 0 || c.SimilarityThreshold > 1 {
		return errors.New("similarity threshold must be between 0 and 1")
	}
	if c.ChallengeDifficulty < 0 {
		return errors.New("challenge difficulty must be non-negative")
	}
	return nil
}

// DefaultDaemonConfig returns a DaemonConfig with sensible defaults.
func DefaultDaemonConfig() DaemonConfig {
	paths := config.DefaultPaths()
	defaults := config.DefaultAgentConfig()

	return DaemonConfig{
		SocketPath:          paths.AgentSocket,
		IdentityPath:        paths.IdentityPath,
		Port:                defaults.Network.Port,
		DNSSeeds:            defaults.Discovery.DNSSeeds,
		Bootstrap:           defaults.Discovery.Bootstrap,
		MDNSEnabled:         defaults.Discovery.MDNSEnabled,
		SimilarityThreshold: defaults.Protocol.SimilarityThreshold,
		ChallengeDifficulty: defaults.Protocol.ChallengeDifficulty,
		IngestSocket:        paths.IngestSocket,
	}
}

// Daemon is the agent daemon that participates in the P2P network.
type Daemon struct {
	pb.UnimplementedAgentServiceServer

	cfg       DaemonConfig
	identity  *crypto.Identity
	host      *agent.Host
	dht       *agent.DHT
	discovery *discovery.Manager
	server    *grpc.Server
	listener  net.Listener
	logger    *slog.Logger

	// State tracking
	state   string
	stateMu sync.RWMutex
}

// NewDaemon creates a new agent daemon.
func NewDaemon(cfg DaemonConfig) (*Daemon, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Create logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Ensure data directory exists
	if err := os.MkdirAll(filepath.Dir(cfg.IdentityPath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Load or generate identity
	identity, err := loadOrGenerateIdentity(cfg.IdentityPath, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to load/generate identity: %w", err)
	}

	// Create libp2p host
	ctx := context.Background()
	host, err := agent.NewHost(ctx, cfg.Port)
	if err != nil {
		return nil, fmt.Errorf("failed to create host: %w", err)
	}

	// Create DHT
	dht, err := agent.NewDHT(ctx, host)
	if err != nil {
		host.Close()
		return nil, fmt.Errorf("failed to create DHT: %w", err)
	}

	// Create discovery manager
	discMgr := discovery.NewManager(discovery.ManagerConfig{
		DNSSeeds:    cfg.DNSSeeds,
		Bootstrap:   cfg.Bootstrap,
		MDNSEnabled: cfg.MDNSEnabled,
	})

	d := &Daemon{
		cfg:       cfg,
		identity:  identity,
		host:      host,
		dht:       dht,
		discovery: discMgr,
		logger:    logger,
		state:     StateIdle,
	}

	return d, nil
}

// loadOrGenerateIdentity loads an existing identity or generates a new one.
func loadOrGenerateIdentity(path string, logger *slog.Logger) (*crypto.Identity, error) {
	// Try to load existing identity
	if _, err := os.Stat(path); err == nil {
		identity, err := crypto.LoadIdentity(path, defaultIdentityPassphrase)
		if err != nil {
			logger.Warn("failed to load existing identity, generating new one",
				"path", path,
				"error", err,
			)
		} else {
			logger.Info("loaded existing identity",
				"path", path,
				"did", identity.DID,
			)
			return identity, nil
		}
	}

	// Generate new identity
	identity, err := crypto.GenerateIdentity()
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity: %w", err)
	}

	// Save the new identity
	if err := crypto.SaveIdentity(identity, path, defaultIdentityPassphrase); err != nil {
		return nil, fmt.Errorf("failed to save identity: %w", err)
	}

	logger.Info("generated new identity",
		"path", path,
		"did", identity.DID,
	)

	return identity, nil
}

// Run starts the daemon and blocks until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	// Ensure data directory exists
	if err := os.MkdirAll(filepath.Dir(d.cfg.SocketPath), 0700); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Remove existing socket if present
	if err := os.Remove(d.cfg.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	// Create Unix socket listener
	listener, err := net.Listen("unix", d.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket: %w", err)
	}
	d.listener = listener

	// Create gRPC server
	d.server = grpc.NewServer()
	pb.RegisterAgentServiceServer(d.server, d)

	// Start gRPC server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		d.logger.Info("starting gRPC server", "socket", d.cfg.SocketPath)
		serverErr <- d.server.Serve(listener)
	}()

	// Bootstrap DHT
	if err := d.dht.Bootstrap(ctx); err != nil {
		d.logger.Warn("DHT bootstrap error", "error", err)
	}

	// Discover and connect to bootstrap peers
	go d.discoverPeers(ctx)

	d.logger.Info("agent daemon running",
		"peer_id", d.host.ID().String(),
		"did", d.identity.DID,
		"addrs", formatAddrs(d.host.Addrs()),
	)

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		d.logger.Info("shutting down daemon")
	case err := <-serverErr:
		if err != nil {
			d.logger.Error("server error", "error", err)
		}
	}

	// Graceful shutdown
	return d.shutdown()
}

// discoverPeers runs peer discovery in the background.
func (d *Daemon) discoverPeers(ctx context.Context) {
	d.setState(StateDiscovering)
	defer d.setState(StateIdle)

	peers := d.discovery.DiscoverPeers(ctx)
	if len(peers) == 0 {
		d.logger.Info("no bootstrap peers discovered")
		return
	}

	d.logger.Info("discovered peers", "count", len(peers))

	d.setState(StateConnecting)
	connected := 0
	for _, peerInfo := range peers {
		if err := d.host.Connect(ctx, peerInfo); err != nil {
			d.logger.Warn("failed to connect to peer",
				"peer_id", peerInfo.ID.String(),
				"error", err,
			)
			continue
		}
		connected++
		d.logger.Info("connected to peer", "peer_id", peerInfo.ID.String())
	}

	if connected > 0 {
		d.setState(StateActive)
	}
}

// shutdown performs graceful shutdown.
func (d *Daemon) shutdown() error {
	var errs []error

	// Stop gRPC server
	if d.server != nil {
		d.server.GracefulStop()
	}

	// Remove socket file
	if d.cfg.SocketPath != "" {
		if err := os.Remove(d.cfg.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("failed to remove socket: %w", err))
		}
	}

	// Close DHT
	if d.dht != nil {
		if err := d.dht.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close DHT: %w", err))
		}
	}

	// Close host
	if d.host != nil {
		if err := d.host.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close host: %w", err))
		}
	}

	// Save identity
	if d.identity != nil && d.cfg.IdentityPath != "" {
		if err := crypto.SaveIdentity(d.identity, d.cfg.IdentityPath, defaultIdentityPassphrase); err != nil {
			errs = append(errs, fmt.Errorf("failed to save identity: %w", err))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// Close closes the daemon without running the full shutdown sequence.
// This is useful for tests that don't call Run().
func (d *Daemon) Close() error {
	var errs []error

	if d.dht != nil {
		if err := d.dht.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if d.host != nil {
		if err := d.host.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// setState updates the daemon state.
func (d *Daemon) setState(state string) {
	d.stateMu.Lock()
	defer d.stateMu.Unlock()
	d.state = state
}

// getState returns the current daemon state.
func (d *Daemon) getState() string {
	d.stateMu.RLock()
	defer d.stateMu.RUnlock()
	return d.state
}

// Status implements pb.AgentServiceServer.
func (d *Daemon) Status(ctx context.Context, req *pb.AgentStatusRequest) (*pb.AgentStatusResponse, error) {
	connectedPeers := len(d.host.Peers())

	return &pb.AgentStatusResponse{
		Ready:            true,
		PeerId:           d.host.ID().String(),
		ConnectedPeers:   int32(connectedPeers),
		ActiveHandshakes: 0, // TODO: implement handshake tracking
		State:            d.getState(),
	}, nil
}

// Peers implements pb.AgentServiceServer.
func (d *Daemon) Peers(ctx context.Context, req *pb.PeersRequest) (*pb.PeersResponse, error) {
	peerIDs := d.host.Peers()
	// Always return a non-nil slice
	peers := []*pb.PeerInfo{}

	for _, pid := range peerIDs {
		// Get connection info
		conns := d.host.Host().Network().ConnsToPeer(pid)
		var addrs []string
		var connState string

		if len(conns) > 0 {
			for _, conn := range conns {
				addrs = append(addrs, conn.RemoteMultiaddr().String())
			}
			connState = connectionStateString(conns[0].Stat().Direction)
		} else {
			connState = "disconnected"
		}

		peers = append(peers, &pb.PeerInfo{
			PeerId:          pid.String(),
			Addrs:           addrs,
			ConnectionState: connState,
		})
	}

	return &pb.PeersResponse{
		Peers: peers,
	}, nil
}

// Bootstrap implements pb.AgentServiceServer.
func (d *Daemon) Bootstrap(ctx context.Context, req *pb.BootstrapRequest) (*pb.BootstrapResponse, error) {
	// Parse multiaddr
	ma, err := multiaddr.NewMultiaddr(req.Multiaddr)
	if err != nil {
		return &pb.BootstrapResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid multiaddr: %v", err),
		}, nil
	}

	// Extract peer info
	addrInfo, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		return &pb.BootstrapResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to parse peer info: %v", err),
		}, nil
	}

	// Connect to peer
	if err := d.host.Connect(ctx, *addrInfo); err != nil {
		return &pb.BootstrapResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to connect: %v", err),
		}, nil
	}

	d.logger.Info("manually connected to peer", "peer_id", addrInfo.ID.String())

	return &pb.BootstrapResponse{
		Success: true,
		PeerId:  addrInfo.ID.String(),
	}, nil
}

// Identity implements pb.AgentServiceServer.
func (d *Daemon) Identity(ctx context.Context, req *pb.IdentityRequest) (*pb.IdentityResponse, error) {
	addrs := d.host.Addrs()
	listenAddrs := make([]string, len(addrs))
	for i, addr := range addrs {
		listenAddrs[i] = addr.String()
	}

	return &pb.IdentityResponse{
		PeerId:      d.host.ID().String(),
		Did:         d.identity.DID,
		ListenAddrs: listenAddrs,
	}, nil
}

// connectionStateString converts a network direction to a human-readable string.
func connectionStateString(dir network.Direction) string {
	switch dir {
	case network.DirInbound:
		return "inbound"
	case network.DirOutbound:
		return "outbound"
	default:
		return "unknown"
	}
}

// formatAddrs formats multiaddrs for logging.
func formatAddrs(addrs []multiaddr.Multiaddr) []string {
	result := make([]string, len(addrs))
	for i, addr := range addrs {
		result[i] = addr.String()
	}
	return result
}

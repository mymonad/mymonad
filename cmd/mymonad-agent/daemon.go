package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
	"github.com/mymonad/mymonad/internal/agent"
	"github.com/mymonad/mymonad/internal/antispam"
	"github.com/mymonad/mymonad/internal/chat"
	"github.com/mymonad/mymonad/internal/config"
	"github.com/mymonad/mymonad/internal/crypto"
	"github.com/mymonad/mymonad/internal/discovery"
	"github.com/mymonad/mymonad/internal/handshake"
	"github.com/mymonad/mymonad/pkg/lsh"
	"github.com/mymonad/mymonad/pkg/monad"

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

// identityPassphraseEnvVar is the environment variable for the identity passphrase.
const identityPassphraseEnvVar = "MYMONAD_IDENTITY_PASSPHRASE"

// getIdentityPassphrase returns the identity passphrase from environment or default.
// SECURITY: In production, always set MYMONAD_IDENTITY_PASSPHRASE environment variable.
// Using the default passphrase is insecure as it's hardcoded in the binary.
func getIdentityPassphrase() string {
	if passphrase := os.Getenv(identityPassphraseEnvVar); passphrase != "" {
		return passphrase
	}
	return "mymonad-agent-identity-default"
}

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

// LSH signature generation constants
const (
	// LSHNumHashes is the number of hash bits for LSH signatures.
	// 256 bits provides good accuracy for similarity estimation.
	LSHNumHashes = 256
	// LSHDimensions is the expected Monad vector dimensions.
	// Must match the embedding model dimensions (384 for most models).
	LSHDimensions = 384
	// LSHSeed is the deterministic seed for hyperplane generation.
	// All nodes must use the same seed for compatible signatures.
	LSHSeed = 42
)

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

	// Handshake protocol components
	handshakeManager *handshake.Manager
	handshakeHandler *handshake.StreamHandler

	// Anti-spam service for PoW-based protection
	antiSpam *antispam.AntiSpamService

	// Chat service for encrypted human-to-human communication
	chatService *chat.ChatService

	// LSH discovery components
	lshDiscovery    *discovery.LSHDiscoveryManager
	lshGenerator    *lsh.Generator
	lastMonadHash   [32]byte // Hash of last processed Monad for change detection
	lastMonadHashMu sync.RWMutex

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

	// Create handshake manager
	handshakeMgr := handshake.NewManager(host.Host(), handshake.ManagerConfig{
		AutoInitiate:     true,
		CooldownDuration: 1 * time.Hour,
		Threshold:        float32(cfg.SimilarityThreshold),
	})

	// Create and register stream handler
	handshakeHandler := handshake.NewStreamHandler(handshakeMgr, logger)
	handshakeHandler.Register(host.Host())

	// Create chat service with adapter for handshake manager
	// The host satisfies the StreamOpener interface
	chatSvc := chat.NewChatService(host.Host(), newHandshakeManagerAdapter(handshakeMgr))

	// Register chat stream handler for incoming chat connections
	host.Host().SetStreamHandler(chat.ChatProtocolID, func(s network.Stream) {
		// For now, log incoming chat streams
		// In a full implementation, this would be handled by the chat service
		logger.Info("received incoming chat stream",
			"peer", s.Conn().RemotePeer().String(),
			"protocol", s.Protocol(),
		)
		// Reset the stream since we're not handling incoming streams yet
		// This will be implemented in a future task
		s.Reset()
	})

	// Create LSH discovery manager for similarity-based peer discovery
	lshDiscoveryMgr := discovery.NewLSHDiscoveryManager(discovery.DefaultLSHDiscoveryConfig())

	// Create LSH signature generator for Monad signatures
	lshGen := lsh.NewGenerator(LSHNumHashes, LSHDimensions, LSHSeed)

	d := &Daemon{
		cfg:              cfg,
		identity:         identity,
		host:             host,
		dht:              dht,
		discovery:        discMgr,
		handshakeManager: handshakeMgr,
		handshakeHandler: handshakeHandler,
		chatService:      chatSvc,
		lshDiscovery:     lshDiscoveryMgr,
		lshGenerator:     lshGen,
		logger:           logger,
		state:            StateIdle,
	}

	// Initialize anti-spam service
	d.initAntiSpam()

	return d, nil
}

// initAntiSpam initializes the anti-spam service and wires it to the handshake manager.
// The anti-spam service provides load-adaptive PoW challenges to prevent spam attacks.
func (d *Daemon) initAntiSpam() {
	// Use default configuration for anti-spam service
	config := antispam.DefaultDifficultyConfig()

	d.antiSpam = antispam.NewAntiSpamService(config)
	d.handshakeManager.SetAntiSpamService(d.antiSpam)

	// Log tier changes for monitoring
	d.antiSpam.SetOnTierChange(func(tier antispam.DifficultyTier) {
		d.logger.Warn("anti-spam difficulty changed",
			"tier", tier.String(),
			"bits", tier.Bits(),
		)
	})
}

// loadOrGenerateIdentity loads an existing identity or generates a new one.
func loadOrGenerateIdentity(path string, logger *slog.Logger) (*crypto.Identity, error) {
	// Try to load existing identity
	if _, err := os.Stat(path); err == nil {
		identity, err := crypto.LoadIdentity(path, getIdentityPassphrase())
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
	if err := crypto.SaveIdentity(identity, path, getIdentityPassphrase()); err != nil {
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

	// Start handshake cleanup loop
	go d.handshakeManager.CleanupLoop(ctx, 5*time.Minute)

	// Start LSH discovery loop for similarity-based peer discovery
	go d.lshDiscovery.DiscoveryLoop(ctx)

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

	peers := d.discovery.DiscoverPeers(ctx)
	if len(peers) == 0 {
		d.logger.Info("no bootstrap peers discovered")
		d.setState(StateIdle)
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
	} else {
		d.setState(StateIdle)
	}
}

// HandleMonadUpdated is called when the Monad is updated to regenerate the LSH signature.
// It checks if the Monad has changed since the last update and regenerates the signature
// if necessary. This enables similarity-based peer discovery.
//
// The method computes a hash of the Monad to detect changes, avoiding unnecessary
// signature regeneration for unchanged Monads.
func (d *Daemon) HandleMonadUpdated(newMonad *monad.Monad) {
	if newMonad == nil {
		d.logger.Warn("HandleMonadUpdated called with nil Monad")
		return
	}

	// Compute hash of Monad for change detection
	newHash := d.computeMonadHash(newMonad)

	// Check if signature needs regeneration
	d.lastMonadHashMu.RLock()
	needsRegen := newHash != d.lastMonadHash
	d.lastMonadHashMu.RUnlock()

	if !needsRegen {
		d.logger.Debug("Monad unchanged, skipping signature regeneration")
		return
	}

	// Generate new LSH signature from Monad
	monadSig := d.lshGenerator.Generate(newMonad)
	if monadSig == nil {
		d.logger.Warn("failed to generate LSH signature from Monad",
			"monad_dimensions", newMonad.Dimensions(),
			"expected_dimensions", LSHDimensions,
		)
		return
	}

	// Update the LSH discovery manager with the new signature
	d.lshDiscovery.SetLocalSignature(monadSig.Signature.Bits)

	// Update the stored hash
	d.lastMonadHashMu.Lock()
	d.lastMonadHash = newHash
	d.lastMonadHashMu.Unlock()

	d.logger.Info("LSH signature updated from Monad",
		"monad_version", newMonad.GetVersion(),
		"monad_doc_count", newMonad.GetDocCount(),
		"signature_size", monadSig.Signature.Size,
	)
}

// computeMonadHash computes a SHA-256 hash of the Monad's binary representation.
// This is used for change detection to avoid unnecessary signature regeneration.
func (d *Daemon) computeMonadHash(m *monad.Monad) [32]byte {
	data, err := m.MarshalBinary()
	if err != nil {
		// Return zero hash on error - will cause regeneration
		return [32]byte{}
	}
	return sha256.Sum256(data)
}

// GetLSHDiscoveryManager returns the LSH discovery manager for external access.
// This can be used for testing or advanced integrations.
func (d *Daemon) GetLSHDiscoveryManager() *discovery.LSHDiscoveryManager {
	return d.lshDiscovery
}

// GetChatService returns the chat service for external access.
// This allows other components to access the chat service for encrypted messaging.
func (d *Daemon) GetChatService() *chat.ChatService {
	return d.chatService
}

// GetAntiSpamService returns the anti-spam service for external access.
// This can be used for testing or monitoring.
func (d *Daemon) GetAntiSpamService() *antispam.AntiSpamService {
	return d.antiSpam
}

// shutdownTimeout is the maximum time to wait for graceful shutdown.
const shutdownTimeout = 5 * time.Second

// shutdown performs graceful shutdown.
func (d *Daemon) shutdown() error {
	var errs []error

	// Stop gRPC server with timeout
	if d.server != nil {
		done := make(chan struct{})
		go func() {
			d.server.GracefulStop()
			close(done)
		}()

		select {
		case <-done:
			d.logger.Info("gRPC server stopped gracefully")
		case <-time.After(shutdownTimeout):
			d.logger.Warn("gRPC graceful stop timed out, forcing stop")
			d.server.Stop()
		}
	}

	// Stop anti-spam service
	if d.antiSpam != nil {
		d.antiSpam.Stop()
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
		if err := crypto.SaveIdentity(d.identity, d.cfg.IdentityPath, getIdentityPassphrase()); err != nil {
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

	// Stop anti-spam service
	if d.antiSpam != nil {
		d.antiSpam.Stop()
	}

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
	activeHandshakes := len(d.handshakeManager.ListSessions())

	return &pb.AgentStatusResponse{
		Ready:            true,
		PeerId:           d.host.ID().String(),
		ConnectedPeers:   int32(connectedPeers),
		ActiveHandshakes: int32(activeHandshakes),
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

// StartHandshake implements pb.AgentServiceServer.
func (d *Daemon) StartHandshake(ctx context.Context, req *pb.StartHandshakeRequest) (*pb.StartHandshakeResponse, error) {
	// Parse peer ID
	peerID, err := peer.Decode(req.PeerId)
	if err != nil {
		return &pb.StartHandshakeResponse{
			Error: fmt.Sprintf("invalid peer ID: %v", err),
		}, nil
	}

	// Check if peer is connected
	if d.host.Host().Network().Connectedness(peerID) != network.Connected {
		return &pb.StartHandshakeResponse{
			Error: "peer not connected",
		}, nil
	}

	// Initiate handshake
	session, err := d.handshakeHandler.InitiateHandshake(ctx, d.host.Host(), peerID)
	if err != nil {
		return &pb.StartHandshakeResponse{
			Error: err.Error(),
		}, nil
	}

	d.logger.Info("started handshake", "session_id", session.ID, "peer", peerID.String())

	return &pb.StartHandshakeResponse{
		SessionId: session.ID,
	}, nil
}

// ListHandshakes implements pb.AgentServiceServer.
func (d *Daemon) ListHandshakes(ctx context.Context, req *pb.ListHandshakesRequest) (*pb.ListHandshakesResponse, error) {
	// Use ListSessionsInfo for read-only access to avoid data races
	sessionInfos := d.handshakeManager.ListSessionsInfo()
	handshakes := make([]*pb.HandshakeInfo, 0, len(sessionInfos))

	for _, info := range sessionInfos {
		handshakes = append(handshakes, &pb.HandshakeInfo{
			SessionId:           info.ID,
			PeerId:              info.PeerID,
			State:               info.State,
			Role:                info.Role,
			ElapsedSeconds:      info.ElapsedSeconds,
			PendingApproval:     info.PendingApproval,
			PendingApprovalType: info.ApprovalType,
		})
	}

	return &pb.ListHandshakesResponse{
		Handshakes: handshakes,
	}, nil
}

// GetHandshake implements pb.AgentServiceServer.
func (d *Daemon) GetHandshake(ctx context.Context, req *pb.GetHandshakeRequest) (*pb.GetHandshakeResponse, error) {
	session := d.handshakeManager.GetSession(req.SessionId)
	if session == nil {
		return &pb.GetHandshakeResponse{
			Error: "session not found",
		}, nil
	}

	return &pb.GetHandshakeResponse{
		Handshake: sessionToHandshakeInfo(session),
	}, nil
}

// ApproveHandshake implements pb.AgentServiceServer.
func (d *Daemon) ApproveHandshake(ctx context.Context, req *pb.ApproveHandshakeRequest) (*pb.ApproveHandshakeResponse, error) {
	session := d.handshakeManager.GetSession(req.SessionId)
	if session == nil {
		return &pb.ApproveHandshakeResponse{
			Success: false,
			Error:   "session not found",
		}, nil
	}

	if !session.IsPendingApproval() {
		return &pb.ApproveHandshakeResponse{
			Success: false,
			Error:   "session is not pending approval",
		}, nil
	}

	approvalType := session.GetPendingApprovalType()

	// For unmask approval, set the identity payload
	if approvalType == "unmask" {
		session.SetIdentityPayload(&pb.IdentityPayload{
			DisplayName:  req.DisplayName,
			Email:        req.Email,
			SignalNumber: req.SignalNumber,
			MatrixId:     req.MatrixId,
		})
	}

	// Signal approval to unblock the waiting protocol handler
	if !session.SignalApproval(true) {
		d.logger.Warn("approval signal dropped - channel full, session may have timed out",
			"session_id", session.ID,
		)
		return &pb.ApproveHandshakeResponse{
			Success: false,
			Error:   "approval signal could not be delivered (session may have timed out)",
		}, nil
	}

	d.logger.Info("approved handshake", "session_id", session.ID, "approval_type", approvalType)

	return &pb.ApproveHandshakeResponse{
		Success: true,
	}, nil
}

// RejectHandshake implements pb.AgentServiceServer.
func (d *Daemon) RejectHandshake(ctx context.Context, req *pb.RejectHandshakeRequest) (*pb.RejectHandshakeResponse, error) {
	session := d.handshakeManager.GetSession(req.SessionId)
	if session == nil {
		return &pb.RejectHandshakeResponse{
			Success: false,
			Error:   "session not found",
		}, nil
	}

	d.logger.Info("rejected handshake", "session_id", session.ID, "reason", req.Reason)

	// If session is pending approval, signal rejection
	if session.IsPendingApproval() {
		if !session.SignalApproval(false) {
			d.logger.Warn("rejection signal dropped - channel full, session may have timed out",
				"session_id", session.ID,
			)
		}
	} else {
		// If not pending, just remove the session
		d.handshakeManager.RemoveSession(session.ID)
	}

	return &pb.RejectHandshakeResponse{
		Success: true,
	}, nil
}

// WatchHandshakes implements pb.AgentServiceServer.
func (d *Daemon) WatchHandshakes(req *pb.WatchHandshakesRequest, stream grpc.ServerStreamingServer[pb.HandshakeEvent]) error {
	// Subscribe to handshake events
	events := d.handshakeManager.Subscribe()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case event, ok := <-events:
			if !ok {
				return nil
			}

			pbEvent := &pb.HandshakeEvent{
				SessionId:      event.SessionID,
				EventType:      event.EventType,
				State:          event.State,
				PeerId:         event.PeerID,
				ElapsedSeconds: event.ElapsedSeconds,
			}

			if err := stream.Send(pbEvent); err != nil {
				return err
			}
		}
	}
}

// sessionToHandshakeInfo converts a session to a HandshakeInfo proto message.
// Uses thread-safe accessors to prevent data races.
func sessionToHandshakeInfo(s *handshake.Session) *pb.HandshakeInfo {
	return &pb.HandshakeInfo{
		SessionId:           s.ID,
		PeerId:              s.PeerID.String(),
		State:               s.State().String(),
		Role:                s.Role.String(),
		ElapsedSeconds:      s.ElapsedSeconds(),
		PendingApproval:     s.IsPendingApproval(),
		PendingApprovalType: s.GetPendingApprovalType(),
	}
}

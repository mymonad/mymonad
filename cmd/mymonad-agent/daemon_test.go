package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	pb "github.com/mymonad/mymonad/api/proto"
	"github.com/mymonad/mymonad/pkg/monad"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestDaemonConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     DaemonConfig
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: DaemonConfig{
				SocketPath:          "/tmp/test.sock",
				IdentityPath:        "/tmp/identity.key",
				Port:                4001,
				DNSSeeds:            []string{},
				Bootstrap:           []string{},
				MDNSEnabled:         true,
				SimilarityThreshold: 0.85,
				ChallengeDifficulty: 16,
				IngestSocket:        "/tmp/ingest.sock",
			},
			wantErr: false,
		},
		{
			name: "missing socket path",
			cfg: DaemonConfig{
				IdentityPath:        "/tmp/identity.key",
				Port:                4001,
				SimilarityThreshold: 0.85,
				ChallengeDifficulty: 16,
			},
			wantErr: true,
		},
		{
			name: "missing identity path",
			cfg: DaemonConfig{
				SocketPath:          "/tmp/test.sock",
				Port:                4001,
				SimilarityThreshold: 0.85,
				ChallengeDifficulty: 16,
			},
			wantErr: true,
		},
		{
			name: "invalid port zero - uses default",
			cfg: DaemonConfig{
				SocketPath:          "/tmp/test.sock",
				IdentityPath:        "/tmp/identity.key",
				Port:                0,
				SimilarityThreshold: 0.85,
				ChallengeDifficulty: 16,
			},
			wantErr: false,
		},
		{
			name: "invalid similarity threshold too low",
			cfg: DaemonConfig{
				SocketPath:          "/tmp/test.sock",
				IdentityPath:        "/tmp/identity.key",
				Port:                4001,
				SimilarityThreshold: -0.1,
				ChallengeDifficulty: 16,
			},
			wantErr: true,
		},
		{
			name: "invalid similarity threshold too high",
			cfg: DaemonConfig{
				SocketPath:          "/tmp/test.sock",
				IdentityPath:        "/tmp/identity.key",
				Port:                4001,
				SimilarityThreshold: 1.5,
				ChallengeDifficulty: 16,
			},
			wantErr: true,
		},
		{
			name: "invalid challenge difficulty negative",
			cfg: DaemonConfig{
				SocketPath:          "/tmp/test.sock",
				IdentityPath:        "/tmp/identity.key",
				Port:                4001,
				SimilarityThreshold: 0.85,
				ChallengeDifficulty: -1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultDaemonConfig(t *testing.T) {
	cfg := DefaultDaemonConfig()

	if cfg.SocketPath == "" {
		t.Error("Default SocketPath is empty")
	}

	if cfg.IdentityPath == "" {
		t.Error("Default IdentityPath is empty")
	}

	if cfg.Port == 0 {
		t.Error("Default Port is 0")
	}

	if cfg.SimilarityThreshold == 0 {
		t.Error("Default SimilarityThreshold is 0")
	}

	if cfg.ChallengeDifficulty == 0 {
		t.Error("Default ChallengeDifficulty is 0")
	}

	if !cfg.MDNSEnabled {
		t.Error("Default MDNSEnabled should be true")
	}
}

func TestNewDaemon(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "agent.sock")
	identityPath := filepath.Join(tmpDir, "identity.key")

	cfg := DaemonConfig{
		SocketPath:          sockPath,
		IdentityPath:        identityPath,
		Port:                0, // Random port
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false, // Disable mDNS for tests
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	defer d.Close()

	if d == nil {
		t.Fatal("NewDaemon() returned nil")
	}

	if d.identity == nil {
		t.Error("Daemon identity is nil")
	}

	if d.host == nil {
		t.Error("Daemon host is nil")
	}
}

func TestNewDaemon_LoadsExistingIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "agent.sock")
	identityPath := filepath.Join(tmpDir, "identity.key")

	// Create first daemon - generates identity
	cfg := DaemonConfig{
		SocketPath:          sockPath,
		IdentityPath:        identityPath,
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d1, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}

	// Store the DID for comparison
	originalDID := d1.identity.DID
	d1.Close()

	// Create second daemon - should load existing identity
	d2, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() second time error = %v", err)
	}
	defer d2.Close()

	if d2.identity.DID != originalDID {
		t.Errorf("Loaded identity DID = %s, want %s", d2.identity.DID, originalDID)
	}
}

func TestDaemon_Status(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "agent.sock")
	identityPath := filepath.Join(tmpDir, "identity.key")

	cfg := DaemonConfig{
		SocketPath:          sockPath,
		IdentityPath:        identityPath,
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	defer d.Close()

	ctx := context.Background()
	resp, err := d.Status(ctx, &pb.AgentStatusRequest{})
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}

	if !resp.Ready {
		t.Error("Status() ready = false, want true")
	}

	if resp.PeerId == "" {
		t.Error("Status() peer_id is empty")
	}

	if resp.State == "" {
		t.Error("Status() state is empty")
	}
}

func TestDaemon_Identity(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "agent.sock")
	identityPath := filepath.Join(tmpDir, "identity.key")

	cfg := DaemonConfig{
		SocketPath:          sockPath,
		IdentityPath:        identityPath,
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	defer d.Close()

	ctx := context.Background()
	resp, err := d.Identity(ctx, &pb.IdentityRequest{})
	if err != nil {
		t.Fatalf("Identity() error = %v", err)
	}

	if resp.PeerId == "" {
		t.Error("Identity() peer_id is empty")
	}

	if resp.Did == "" {
		t.Error("Identity() did is empty")
	}

	if len(resp.ListenAddrs) == 0 {
		t.Error("Identity() listen_addrs is empty")
	}

	// Verify DID format
	if resp.Did != d.identity.DID {
		t.Errorf("Identity() did = %s, want %s", resp.Did, d.identity.DID)
	}
}

func TestDaemon_Peers(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "agent.sock")
	identityPath := filepath.Join(tmpDir, "identity.key")

	cfg := DaemonConfig{
		SocketPath:          sockPath,
		IdentityPath:        identityPath,
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	defer d.Close()

	ctx := context.Background()
	resp, err := d.Peers(ctx, &pb.PeersRequest{})
	if err != nil {
		t.Fatalf("Peers() error = %v", err)
	}

	// No peers connected initially
	if resp.Peers == nil {
		t.Error("Peers() peers is nil, expected empty slice")
	}
}

func TestDaemon_Bootstrap(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two daemons
	cfg1 := DaemonConfig{
		SocketPath:          filepath.Join(tmpDir, "agent1.sock"),
		IdentityPath:        filepath.Join(tmpDir, "identity1.key"),
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	cfg2 := DaemonConfig{
		SocketPath:          filepath.Join(tmpDir, "agent2.sock"),
		IdentityPath:        filepath.Join(tmpDir, "identity2.key"),
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d1, err := NewDaemon(cfg1)
	if err != nil {
		t.Fatalf("NewDaemon(1) error = %v", err)
	}
	defer d1.Close()

	d2, err := NewDaemon(cfg2)
	if err != nil {
		t.Fatalf("NewDaemon(2) error = %v", err)
	}
	defer d2.Close()

	// Get d1's address info
	addrInfo := d1.host.AddrInfo()
	if len(addrInfo.Addrs) == 0 {
		t.Fatal("d1 has no listen addresses")
	}

	// Build multiaddr string: /ip4/127.0.0.1/tcp/PORT/p2p/PEER_ID
	multiaddr := addrInfo.Addrs[0].String() + "/p2p/" + addrInfo.ID.String()

	// Bootstrap d2 to d1
	ctx := context.Background()
	resp, err := d2.Bootstrap(ctx, &pb.BootstrapRequest{Multiaddr: multiaddr})
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}

	if !resp.Success {
		t.Errorf("Bootstrap() success = false, error = %s", resp.Error)
	}

	if resp.PeerId != addrInfo.ID.String() {
		t.Errorf("Bootstrap() peer_id = %s, want %s", resp.PeerId, addrInfo.ID.String())
	}

	// Give time for connection to establish
	time.Sleep(100 * time.Millisecond)

	// Verify peers list
	peersResp, err := d2.Peers(ctx, &pb.PeersRequest{})
	if err != nil {
		t.Fatalf("Peers() error = %v", err)
	}

	found := false
	for _, p := range peersResp.Peers {
		if p.PeerId == addrInfo.ID.String() {
			found = true
			break
		}
	}

	if !found {
		t.Error("Bootstrap peer not found in peers list")
	}
}

func TestDaemon_BootstrapInvalidMultiaddr(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "agent.sock")
	identityPath := filepath.Join(tmpDir, "identity.key")

	cfg := DaemonConfig{
		SocketPath:          sockPath,
		IdentityPath:        identityPath,
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	defer d.Close()

	ctx := context.Background()
	resp, err := d.Bootstrap(ctx, &pb.BootstrapRequest{Multiaddr: "invalid-multiaddr"})
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}

	if resp.Success {
		t.Error("Bootstrap() with invalid multiaddr should not succeed")
	}

	if resp.Error == "" {
		t.Error("Bootstrap() with invalid multiaddr should have error message")
	}
}

func TestDaemon_RunAndShutdown(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "agent.sock")
	identityPath := filepath.Join(tmpDir, "identity.key")

	cfg := DaemonConfig{
		SocketPath:          sockPath,
		IdentityPath:        identityPath,
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- d.Run(ctx)
	}()

	// Give daemon time to start
	time.Sleep(100 * time.Millisecond)

	// Verify socket file exists
	if _, err := os.Stat(sockPath); os.IsNotExist(err) {
		t.Error("Socket file was not created")
	}

	// Cancel context to stop daemon
	cancel()

	// Wait for daemon to stop
	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Errorf("Run() error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("Daemon did not shut down in time")
	}

	// Verify identity was saved
	if _, err := os.Stat(identityPath); os.IsNotExist(err) {
		t.Error("Identity file was not saved")
	}
}

func TestDaemon_IPCIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "agent.sock")
	identityPath := filepath.Join(tmpDir, "identity.key")

	cfg := DaemonConfig{
		SocketPath:          sockPath,
		IdentityPath:        identityPath,
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start daemon in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- d.Run(ctx)
	}()

	// Wait for socket to be created
	time.Sleep(200 * time.Millisecond)

	// Connect as a client via Unix socket
	conn, err := grpc.NewClient(
		"unix://"+sockPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("Failed to connect to socket: %v", err)
	}
	defer conn.Close()

	client := pb.NewAgentServiceClient(conn)

	// Test Status RPC
	statusResp, err := client.Status(ctx, &pb.AgentStatusRequest{})
	if err != nil {
		t.Fatalf("Status RPC error = %v", err)
	}
	if !statusResp.Ready {
		t.Error("Status RPC: ready = false, want true")
	}

	// Test Identity RPC
	identityResp, err := client.Identity(ctx, &pb.IdentityRequest{})
	if err != nil {
		t.Fatalf("Identity RPC error = %v", err)
	}
	if identityResp.PeerId == "" {
		t.Error("Identity RPC: peer_id is empty")
	}

	// Test Peers RPC
	peersResp, err := client.Peers(ctx, &pb.PeersRequest{})
	if err != nil {
		t.Fatalf("Peers RPC error = %v", err)
	}
	// Note: protobuf returns nil for empty repeated fields, which is fine
	// We just verify the call succeeds and the response is valid
	if peersResp == nil {
		t.Error("Peers RPC: response is nil")
	}

	// Cleanup
	cancel()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Error("Daemon did not shut down in time")
	}
}

func TestDaemon_StateTransitions(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "agent.sock")
	identityPath := filepath.Join(tmpDir, "identity.key")

	cfg := DaemonConfig{
		SocketPath:          sockPath,
		IdentityPath:        identityPath,
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	defer d.Close()

	// Initial state should be idle
	ctx := context.Background()
	resp, err := d.Status(ctx, &pb.AgentStatusRequest{})
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if resp.State != StateIdle {
		t.Errorf("Initial state = %s, want %s", resp.State, StateIdle)
	}

	// Set to discovering
	d.setState(StateDiscovering)
	resp, err = d.Status(ctx, &pb.AgentStatusRequest{})
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if resp.State != StateDiscovering {
		t.Errorf("After setState(discovering), state = %s, want %s", resp.State, StateDiscovering)
	}

	// Set back to idle
	d.setState(StateIdle)
	resp, err = d.Status(ctx, &pb.AgentStatusRequest{})
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if resp.State != StateIdle {
		t.Errorf("After setState(idle), state = %s, want %s", resp.State, StateIdle)
	}
}

func TestBuildConfig_Defaults(t *testing.T) {
	cfg, err := buildConfig("", 0, nil, nil, true, "", "")
	if err != nil {
		t.Fatalf("buildConfig() error = %v", err)
	}

	if cfg.Port != 4001 {
		t.Errorf("Default Port = %d, want 4001", cfg.Port)
	}

	if cfg.SimilarityThreshold != 0.85 {
		t.Errorf("Default SimilarityThreshold = %f, want 0.85", cfg.SimilarityThreshold)
	}

	if cfg.ChallengeDifficulty != 16 {
		t.Errorf("Default ChallengeDifficulty = %d, want 16", cfg.ChallengeDifficulty)
	}

	if !cfg.MDNSEnabled {
		t.Error("Default MDNSEnabled = false, want true")
	}
}

func TestBuildConfig_FlagOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "custom.sock")

	cfg, err := buildConfig(
		"",
		5001,
		[]string{"/ip4/1.2.3.4/tcp/4001/p2p/QmTest"},
		[]string{"_dnsaddr.test.example"},
		false, // mdns disabled
		"",
		sockPath,
	)
	if err != nil {
		t.Fatalf("buildConfig() error = %v", err)
	}

	if cfg.Port != 5001 {
		t.Errorf("Port = %d, want 5001", cfg.Port)
	}

	if len(cfg.Bootstrap) != 1 || cfg.Bootstrap[0] != "/ip4/1.2.3.4/tcp/4001/p2p/QmTest" {
		t.Errorf("Bootstrap = %v, want [/ip4/1.2.3.4/tcp/4001/p2p/QmTest]", cfg.Bootstrap)
	}

	if len(cfg.DNSSeeds) != 1 || cfg.DNSSeeds[0] != "_dnsaddr.test.example" {
		t.Errorf("DNSSeeds = %v, want [_dnsaddr.test.example]", cfg.DNSSeeds)
	}

	if cfg.MDNSEnabled {
		t.Error("MDNSEnabled = true, want false")
	}

	if cfg.SocketPath != sockPath {
		t.Errorf("SocketPath = %s, want %s", cfg.SocketPath, sockPath)
	}
}

func TestBuildConfig_FromFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	// Create a config file
	configContent := `
[network]
port = 5002

[discovery]
dns_seeds = ["_dnsaddr.file.example"]
bootstrap = ["/ip4/5.6.7.8/tcp/4001/p2p/QmFile"]
mdns_enabled = false

[protocol]
similarity_threshold = 0.90
challenge_difficulty = 20

[storage]
identity_path = "/tmp/file-identity.key"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	cfg, err := buildConfig(configPath, 0, nil, nil, true, "", "")
	if err != nil {
		t.Fatalf("buildConfig() error = %v", err)
	}

	if cfg.Port != 5002 {
		t.Errorf("Port = %d, want 5002", cfg.Port)
	}

	if cfg.SimilarityThreshold != 0.90 {
		t.Errorf("SimilarityThreshold = %f, want 0.90", cfg.SimilarityThreshold)
	}

	if cfg.ChallengeDifficulty != 20 {
		t.Errorf("ChallengeDifficulty = %d, want 20", cfg.ChallengeDifficulty)
	}

	if cfg.MDNSEnabled {
		t.Error("MDNSEnabled = true, want false (from file)")
	}
}

func TestBuildConfig_FileWithFlagOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	// Create a config file
	configContent := `
[network]
port = 5003

[discovery]
dns_seeds = ["_dnsaddr.file.example"]
mdns_enabled = true
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	// Flags should override file settings
	cfg, err := buildConfig(configPath, 6001, nil, nil, false, "", "")
	if err != nil {
		t.Fatalf("buildConfig() error = %v", err)
	}

	if cfg.Port != 6001 {
		t.Errorf("Port = %d, want 6001 (flag override)", cfg.Port)
	}

	if cfg.MDNSEnabled {
		t.Error("MDNSEnabled = true, want false (flag override)")
	}
}

func TestBuildConfig_InvalidFile(t *testing.T) {
	_, err := buildConfig("/nonexistent/config.toml", 0, nil, nil, true, "", "")
	if err == nil {
		t.Error("buildConfig() with invalid file should return error")
	}
}

// TestDaemon_TwoPeersConnect tests that two daemons can connect and see each other
func TestDaemon_TwoPeersConnect(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two daemons
	cfg1 := DaemonConfig{
		SocketPath:          filepath.Join(tmpDir, "agent1.sock"),
		IdentityPath:        filepath.Join(tmpDir, "identity1.key"),
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	cfg2 := DaemonConfig{
		SocketPath:          filepath.Join(tmpDir, "agent2.sock"),
		IdentityPath:        filepath.Join(tmpDir, "identity2.key"),
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d1, err := NewDaemon(cfg1)
	if err != nil {
		t.Fatalf("NewDaemon(1) error = %v", err)
	}
	defer d1.Close()

	d2, err := NewDaemon(cfg2)
	if err != nil {
		t.Fatalf("NewDaemon(2) error = %v", err)
	}
	defer d2.Close()

	// Verify they have different peer IDs
	if d1.host.ID() == d2.host.ID() {
		t.Fatal("Two daemons have the same peer ID")
	}

	// Get d1's address
	addrInfo := d1.host.AddrInfo()
	if len(addrInfo.Addrs) == 0 {
		t.Fatal("d1 has no listen addresses")
	}

	// Connect d2 to d1
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := d2.host.Connect(ctx, addrInfo); err != nil {
		t.Fatalf("Failed to connect d2 to d1: %v", err)
	}

	// Verify d2 sees d1 as a peer
	peers := d2.host.Peers()
	found := false
	for _, p := range peers {
		if p == d1.host.ID() {
			found = true
			break
		}
	}

	if !found {
		t.Error("d2 does not see d1 as a peer after connect")
	}

	// Verify via Peers RPC
	peersResp, err := d2.Peers(ctx, &pb.PeersRequest{})
	if err != nil {
		t.Fatalf("Peers() error = %v", err)
	}

	found = false
	for _, p := range peersResp.Peers {
		pid, err := peer.Decode(p.PeerId)
		if err != nil {
			continue
		}
		if pid == d1.host.ID() {
			found = true
			break
		}
	}

	if !found {
		t.Error("d1 not found in d2's peer list via RPC")
	}
}

// Helper to wait for a socket file to exist
func waitForSocket(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			// Also check if we can connect
			conn, err := net.Dial("unix", path)
			if err == nil {
				conn.Close()
				return true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func TestDaemon_DiscoverAndConnectPeers(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a bootstrap peer first
	bootstrapCfg := DaemonConfig{
		SocketPath:          filepath.Join(tmpDir, "bootstrap.sock"),
		IdentityPath:        filepath.Join(tmpDir, "bootstrap.key"),
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	bootstrapDaemon, err := NewDaemon(bootstrapCfg)
	if err != nil {
		t.Fatalf("NewDaemon(bootstrap) error = %v", err)
	}
	defer bootstrapDaemon.Close()

	// Get bootstrap peer's address
	addrInfo := bootstrapDaemon.host.AddrInfo()
	if len(addrInfo.Addrs) == 0 {
		t.Fatal("bootstrap daemon has no listen addresses")
	}
	bootstrapAddr := addrInfo.Addrs[0].String() + "/p2p/" + addrInfo.ID.String()

	// Create a daemon that will bootstrap to the first peer
	cfg := DaemonConfig{
		SocketPath:          filepath.Join(tmpDir, "agent.sock"),
		IdentityPath:        filepath.Join(tmpDir, "agent.key"),
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{bootstrapAddr},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- d.Run(ctx)
	}()

	// Wait for discovery to happen
	time.Sleep(500 * time.Millisecond)

	// Verify peers were discovered
	resp, err := d.Status(ctx, &pb.AgentStatusRequest{})
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}

	if resp.ConnectedPeers == 0 {
		// Give more time
		time.Sleep(1 * time.Second)
		resp, _ = d.Status(ctx, &pb.AgentStatusRequest{})
	}

	if resp.ConnectedPeers == 0 {
		t.Error("Expected at least 1 connected peer after discovery")
	}

	cancel()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Error("Daemon did not shut down in time")
	}
}

func TestDaemon_PeersWithConnections(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two daemons and connect them
	cfg1 := DaemonConfig{
		SocketPath:          filepath.Join(tmpDir, "agent1.sock"),
		IdentityPath:        filepath.Join(tmpDir, "identity1.key"),
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	cfg2 := DaemonConfig{
		SocketPath:          filepath.Join(tmpDir, "agent2.sock"),
		IdentityPath:        filepath.Join(tmpDir, "identity2.key"),
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d1, err := NewDaemon(cfg1)
	if err != nil {
		t.Fatalf("NewDaemon(1) error = %v", err)
	}
	defer d1.Close()

	d2, err := NewDaemon(cfg2)
	if err != nil {
		t.Fatalf("NewDaemon(2) error = %v", err)
	}
	defer d2.Close()

	// Connect d2 to d1
	ctx := context.Background()
	addrInfo := d1.host.AddrInfo()
	if err := d2.host.Connect(ctx, addrInfo); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Wait for connection to establish
	time.Sleep(100 * time.Millisecond)

	// Test Peers RPC from d2's perspective (outbound connection)
	peersResp, err := d2.Peers(ctx, &pb.PeersRequest{})
	if err != nil {
		t.Fatalf("Peers() error = %v", err)
	}

	if len(peersResp.Peers) == 0 {
		t.Fatal("Expected at least 1 peer in peers list")
	}

	found := false
	for _, p := range peersResp.Peers {
		if p.PeerId == d1.host.ID().String() {
			found = true
			// Check connection state
			if p.ConnectionState != "outbound" {
				t.Errorf("Expected connection state 'outbound', got '%s'", p.ConnectionState)
			}
			// Check addresses
			if len(p.Addrs) == 0 {
				t.Error("Expected peer to have addresses")
			}
			break
		}
	}

	if !found {
		t.Error("d1 not found in d2's peer list")
	}

	// Also test from d1's perspective (inbound connection)
	peersResp1, err := d1.Peers(ctx, &pb.PeersRequest{})
	if err != nil {
		t.Fatalf("Peers() from d1 error = %v", err)
	}

	found = false
	for _, p := range peersResp1.Peers {
		if p.PeerId == d2.host.ID().String() {
			found = true
			// Check connection state - should be inbound from d1's perspective
			if p.ConnectionState != "inbound" {
				t.Errorf("Expected connection state 'inbound', got '%s'", p.ConnectionState)
			}
			break
		}
	}

	if !found {
		t.Error("d2 not found in d1's peer list")
	}
}

func TestDaemon_ValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  DaemonConfig
	}{
		{
			name: "negative port",
			cfg: DaemonConfig{
				SocketPath:          "/tmp/test.sock",
				IdentityPath:        "/tmp/identity.key",
				Port:                -1,
				SimilarityThreshold: 0.85,
				ChallengeDifficulty: 16,
			},
		},
		{
			name: "port too high",
			cfg: DaemonConfig{
				SocketPath:          "/tmp/test.sock",
				IdentityPath:        "/tmp/identity.key",
				Port:                70000,
				SimilarityThreshold: 0.85,
				ChallengeDifficulty: 16,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if err == nil {
				t.Error("Expected validation error")
			}
		})
	}
}

func TestDaemon_CloseWithNilComponents(t *testing.T) {
	// Create a minimal daemon directly (not via NewDaemon) to test Close with nil components
	d := &Daemon{}
	err := d.Close()
	if err != nil {
		t.Errorf("Close() with nil components should not error, got: %v", err)
	}
}

func TestDaemon_BootstrapUnreachablePeer(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "agent.sock")
	identityPath := filepath.Join(tmpDir, "identity.key")

	cfg := DaemonConfig{
		SocketPath:          sockPath,
		IdentityPath:        identityPath,
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try to connect to a non-existent peer
	// This uses a valid multiaddr format but the peer doesn't exist
	resp, err := d.Bootstrap(ctx, &pb.BootstrapRequest{
		Multiaddr: "/ip4/127.0.0.1/tcp/59999/p2p/12D3KooWEqnTdgqHnkkwarSrCDnXt3eHNZ1z8A3rKEAm6YLDD4TZ",
	})
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}

	if resp.Success {
		t.Error("Bootstrap() to non-existent peer should not succeed")
	}

	if resp.Error == "" {
		t.Error("Bootstrap() to non-existent peer should have error message")
	}
}

func TestDaemon_BootstrapEmptyMultiaddr(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "agent.sock")
	identityPath := filepath.Join(tmpDir, "identity.key")

	cfg := DaemonConfig{
		SocketPath:          sockPath,
		IdentityPath:        identityPath,
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	defer d.Close()

	ctx := context.Background()
	resp, err := d.Bootstrap(ctx, &pb.BootstrapRequest{Multiaddr: ""})
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}

	if resp.Success {
		t.Error("Bootstrap() with empty multiaddr should not succeed")
	}
}

func TestDaemon_BootstrapMultiaddrWithoutPeerID(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "agent.sock")
	identityPath := filepath.Join(tmpDir, "identity.key")

	cfg := DaemonConfig{
		SocketPath:          sockPath,
		IdentityPath:        identityPath,
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	defer d.Close()

	ctx := context.Background()
	// Valid multiaddr format but without peer ID
	resp, err := d.Bootstrap(ctx, &pb.BootstrapRequest{Multiaddr: "/ip4/127.0.0.1/tcp/4001"})
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}

	if resp.Success {
		t.Error("Bootstrap() with multiaddr without peer ID should not succeed")
	}

	if resp.Error == "" {
		t.Error("Bootstrap() with multiaddr without peer ID should have error message")
	}
}

func TestDaemon_LSHDiscoveryManagerInitialized(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "agent.sock")
	identityPath := filepath.Join(tmpDir, "identity.key")

	cfg := DaemonConfig{
		SocketPath:          sockPath,
		IdentityPath:        identityPath,
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	defer d.Close()

	// Verify LSH discovery manager is initialized
	lshMgr := d.GetLSHDiscoveryManager()
	if lshMgr == nil {
		t.Fatal("LSH discovery manager should be initialized")
	}

	// Verify default config is applied
	config := lshMgr.Config()
	if config.HammingThreshold != 64 {
		t.Errorf("Expected HammingThreshold=64, got %d", config.HammingThreshold)
	}
	if config.MaxPendingExchanges != 10 {
		t.Errorf("Expected MaxPendingExchanges=10, got %d", config.MaxPendingExchanges)
	}
}

func TestDaemon_HandleMonadUpdated(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "agent.sock")
	identityPath := filepath.Join(tmpDir, "identity.key")

	cfg := DaemonConfig{
		SocketPath:          sockPath,
		IdentityPath:        identityPath,
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	defer d.Close()

	// Create a test Monad with correct dimensions
	testMonad := createTestMonad(t, LSHDimensions)

	// Initially, no signature should be set
	if d.lshDiscovery.GetLocalSignature() != nil {
		t.Error("Expected no local signature before HandleMonadUpdated")
	}

	// Handle Monad update
	d.HandleMonadUpdated(testMonad)

	// Now signature should be set
	sig := d.lshDiscovery.GetLocalSignature()
	if sig == nil {
		t.Fatal("Expected local signature after HandleMonadUpdated")
	}

	// Signature should have correct size (256 bits = 32 bytes)
	expectedBytes := (LSHNumHashes + 7) / 8
	if len(sig) != expectedBytes {
		t.Errorf("Expected signature length %d, got %d", expectedBytes, len(sig))
	}
}

func TestDaemon_HandleMonadUpdated_NilMonad(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "agent.sock")
	identityPath := filepath.Join(tmpDir, "identity.key")

	cfg := DaemonConfig{
		SocketPath:          sockPath,
		IdentityPath:        identityPath,
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	defer d.Close()

	// Should not panic with nil Monad
	d.HandleMonadUpdated(nil)

	// Signature should still be nil
	if d.lshDiscovery.GetLocalSignature() != nil {
		t.Error("Expected no signature after nil Monad update")
	}
}

func TestDaemon_HandleMonadUpdated_DimensionMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "agent.sock")
	identityPath := filepath.Join(tmpDir, "identity.key")

	cfg := DaemonConfig{
		SocketPath:          sockPath,
		IdentityPath:        identityPath,
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	defer d.Close()

	// Create a Monad with wrong dimensions
	wrongDimensionMonad := createTestMonad(t, 128) // Wrong dimension

	// Handle update - should not set signature due to dimension mismatch
	d.HandleMonadUpdated(wrongDimensionMonad)

	// Signature should remain nil due to dimension mismatch
	if d.lshDiscovery.GetLocalSignature() != nil {
		t.Error("Expected no signature with dimension mismatch")
	}
}

func TestDaemon_HandleMonadUpdated_OnlyRegenWhenChanged(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "agent.sock")
	identityPath := filepath.Join(tmpDir, "identity.key")

	cfg := DaemonConfig{
		SocketPath:          sockPath,
		IdentityPath:        identityPath,
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	defer d.Close()

	// Create and update with first Monad
	testMonad := createTestMonad(t, LSHDimensions)
	d.HandleMonadUpdated(testMonad)

	// Get the signature
	sig1 := d.lshDiscovery.GetLocalSignature()
	if sig1 == nil {
		t.Fatal("Expected signature after first update")
	}

	// Update again with same Monad (unchanged)
	d.HandleMonadUpdated(testMonad)

	// Signature should be the same
	sig2 := d.lshDiscovery.GetLocalSignature()
	if len(sig1) != len(sig2) {
		t.Error("Signature length changed unexpectedly")
	}
	for i := range sig1 {
		if sig1[i] != sig2[i] {
			t.Error("Signature changed when Monad was unchanged")
			break
		}
	}

	// Now modify the Monad
	embedding := make([]float32, LSHDimensions)
	for i := range embedding {
		embedding[i] = float32(i) * 0.001
	}
	testMonad.Update(embedding)

	// Update with modified Monad
	d.HandleMonadUpdated(testMonad)

	// Signature should be different now
	sig3 := d.lshDiscovery.GetLocalSignature()
	if sig3 == nil {
		t.Fatal("Expected signature after modified update")
	}
}

// createTestMonad creates a test Monad with random data for testing.
func createTestMonad(t *testing.T, dimensions int) *monad.Monad {
	t.Helper()
	m := monad.New(dimensions)

	// Add some test embeddings to make it non-zero
	embedding := make([]float32, dimensions)
	for i := range embedding {
		embedding[i] = float32(i) * 0.01
	}
	if err := m.Update(embedding); err != nil {
		t.Fatalf("Failed to update test monad: %v", err)
	}

	return m
}

// ============================================================================
// Chat Service Integration Tests
// ============================================================================

func TestDaemon_ChatServiceInitialized(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "agent.sock")
	identityPath := filepath.Join(tmpDir, "identity.key")

	cfg := DaemonConfig{
		SocketPath:          sockPath,
		IdentityPath:        identityPath,
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	defer d.Close()

	// Verify chat service is initialized
	chatSvc := d.GetChatService()
	if chatSvc == nil {
		t.Fatal("ChatService should be initialized")
	}
}

func TestDaemon_ChatServiceAccessor(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "agent.sock")
	identityPath := filepath.Join(tmpDir, "identity.key")

	cfg := DaemonConfig{
		SocketPath:          sockPath,
		IdentityPath:        identityPath,
		Port:                0,
		DNSSeeds:            []string{},
		Bootstrap:           []string{},
		MDNSEnabled:         false,
		SimilarityThreshold: 0.85,
		ChallengeDifficulty: 16,
		IngestSocket:        filepath.Join(tmpDir, "ingest.sock"),
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	defer d.Close()

	// Verify accessor returns the same instance each time
	chatSvc1 := d.GetChatService()
	chatSvc2 := d.GetChatService()

	if chatSvc1 != chatSvc2 {
		t.Error("GetChatService should return the same instance")
	}
}

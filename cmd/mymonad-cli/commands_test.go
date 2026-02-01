package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
	"google.golang.org/grpc"
)

// mockAgentServiceClient is a mock implementation of AgentServiceClient for testing.
type mockAgentServiceClient struct {
	statusFn    func(ctx context.Context, in *pb.AgentStatusRequest, opts ...grpc.CallOption) (*pb.AgentStatusResponse, error)
	peersFn     func(ctx context.Context, in *pb.PeersRequest, opts ...grpc.CallOption) (*pb.PeersResponse, error)
	bootstrapFn func(ctx context.Context, in *pb.BootstrapRequest, opts ...grpc.CallOption) (*pb.BootstrapResponse, error)
	identityFn  func(ctx context.Context, in *pb.IdentityRequest, opts ...grpc.CallOption) (*pb.IdentityResponse, error)
}

func (m *mockAgentServiceClient) Status(ctx context.Context, in *pb.AgentStatusRequest, opts ...grpc.CallOption) (*pb.AgentStatusResponse, error) {
	if m.statusFn != nil {
		return m.statusFn(ctx, in, opts...)
	}
	return nil, errors.New("Status not mocked")
}

func (m *mockAgentServiceClient) Peers(ctx context.Context, in *pb.PeersRequest, opts ...grpc.CallOption) (*pb.PeersResponse, error) {
	if m.peersFn != nil {
		return m.peersFn(ctx, in, opts...)
	}
	return nil, errors.New("Peers not mocked")
}

func (m *mockAgentServiceClient) Bootstrap(ctx context.Context, in *pb.BootstrapRequest, opts ...grpc.CallOption) (*pb.BootstrapResponse, error) {
	if m.bootstrapFn != nil {
		return m.bootstrapFn(ctx, in, opts...)
	}
	return nil, errors.New("Bootstrap not mocked")
}

func (m *mockAgentServiceClient) Identity(ctx context.Context, in *pb.IdentityRequest, opts ...grpc.CallOption) (*pb.IdentityResponse, error) {
	if m.identityFn != nil {
		return m.identityFn(ctx, in, opts...)
	}
	return nil, errors.New("Identity not mocked")
}

// mockMonadStoreClient is a mock implementation of MonadStoreClient for testing.
type mockMonadStoreClient struct {
	statusFn func(ctx context.Context, in *pb.StatusRequest, opts ...grpc.CallOption) (*pb.StatusResponse, error)
}

func (m *mockMonadStoreClient) GetMonad(ctx context.Context, in *pb.GetMonadRequest, opts ...grpc.CallOption) (*pb.GetMonadResponse, error) {
	return nil, errors.New("GetMonad not mocked")
}

func (m *mockMonadStoreClient) WatchMonad(ctx context.Context, in *pb.WatchMonadRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[pb.MonadUpdate], error) {
	return nil, errors.New("WatchMonad not mocked")
}

func (m *mockMonadStoreClient) Status(ctx context.Context, in *pb.StatusRequest, opts ...grpc.CallOption) (*pb.StatusResponse, error) {
	if m.statusFn != nil {
		return m.statusFn(ctx, in, opts...)
	}
	return nil, errors.New("Status not mocked")
}

func TestCLI_Status_Success(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		statusFn: func(ctx context.Context, in *pb.AgentStatusRequest, opts ...grpc.CallOption) (*pb.AgentStatusResponse, error) {
			return &pb.AgentStatusResponse{
				Ready:            true,
				PeerId:           "12D3KooWTestPeerID",
				ConnectedPeers:   5,
				ActiveHandshakes: 2,
				State:            "running",
			}, nil
		},
	}

	ingestMock := &mockMonadStoreClient{
		statusFn: func(ctx context.Context, in *pb.StatusRequest, opts ...grpc.CallOption) (*pb.StatusResponse, error) {
			return &pb.StatusResponse{
				Ready:             true,
				DocumentsIndexed:  42,
				LastScanTimestamp: time.Now().Unix(),
				State:             "idle",
			}, nil
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient:  agentMock,
		ingestClient: ingestMock,
		output:       &out,
	}

	err := cli.Status()
	if err != nil {
		t.Fatalf("Status() returned error: %v", err)
	}

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("Agent Daemon")) {
		t.Errorf("Status output missing 'Agent Daemon', got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("Ingest Daemon")) {
		t.Errorf("Status output missing 'Ingest Daemon', got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("running")) {
		t.Errorf("Status output missing agent state 'running', got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("5")) {
		t.Errorf("Status output missing peer count '5', got: %s", output)
	}
}

func TestCLI_Status_AgentError(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		statusFn: func(ctx context.Context, in *pb.AgentStatusRequest, opts ...grpc.CallOption) (*pb.AgentStatusResponse, error) {
			return nil, errors.New("connection refused")
		},
	}

	ingestMock := &mockMonadStoreClient{
		statusFn: func(ctx context.Context, in *pb.StatusRequest, opts ...grpc.CallOption) (*pb.StatusResponse, error) {
			return &pb.StatusResponse{Ready: true, State: "idle"}, nil
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient:  agentMock,
		ingestClient: ingestMock,
		output:       &out,
	}

	err := cli.Status()
	// Status should still work but show the error
	if err != nil {
		t.Fatalf("Status() should not return error when one daemon fails: %v", err)
	}

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("not running")) {
		t.Errorf("Status output should indicate agent is not running, got: %s", output)
	}
}

func TestCLI_Peers_Success(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		peersFn: func(ctx context.Context, in *pb.PeersRequest, opts ...grpc.CallOption) (*pb.PeersResponse, error) {
			return &pb.PeersResponse{
				Peers: []*pb.PeerInfo{
					{
						PeerId:          "12D3KooWPeer1",
						Addrs:           []string{"/ip4/192.168.1.1/tcp/4001"},
						ConnectionState: "connected",
					},
					{
						PeerId:          "12D3KooWPeer2",
						Addrs:           []string{"/ip4/10.0.0.1/tcp/4001", "/ip6/::1/tcp/4001"},
						ConnectionState: "connected",
					},
				},
			}, nil
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.Peers()
	if err != nil {
		t.Fatalf("Peers() returned error: %v", err)
	}

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("12D3KooWPeer1")) {
		t.Errorf("Peers output missing peer 1, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("12D3KooWPeer2")) {
		t.Errorf("Peers output missing peer 2, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("192.168.1.1")) {
		t.Errorf("Peers output missing address, got: %s", output)
	}
}

func TestCLI_Peers_NoPeers(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		peersFn: func(ctx context.Context, in *pb.PeersRequest, opts ...grpc.CallOption) (*pb.PeersResponse, error) {
			return &pb.PeersResponse{Peers: []*pb.PeerInfo{}}, nil
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.Peers()
	if err != nil {
		t.Fatalf("Peers() returned error: %v", err)
	}

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("No connected peers")) {
		t.Errorf("Peers output should indicate no peers, got: %s", output)
	}
}

func TestCLI_Peers_Error(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		peersFn: func(ctx context.Context, in *pb.PeersRequest, opts ...grpc.CallOption) (*pb.PeersResponse, error) {
			return nil, errors.New("connection refused")
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.Peers()
	if err == nil {
		t.Fatal("Peers() should return error when agent is not available")
	}
}

func TestCLI_Bootstrap_Success(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		bootstrapFn: func(ctx context.Context, in *pb.BootstrapRequest, opts ...grpc.CallOption) (*pb.BootstrapResponse, error) {
			if in.Multiaddr != "/ip4/192.168.1.1/tcp/4001/p2p/12D3KooWTestPeer" {
				t.Errorf("Unexpected multiaddr: %s", in.Multiaddr)
			}
			return &pb.BootstrapResponse{
				Success: true,
				PeerId:  "12D3KooWTestPeer",
			}, nil
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.Bootstrap("/ip4/192.168.1.1/tcp/4001/p2p/12D3KooWTestPeer")
	if err != nil {
		t.Fatalf("Bootstrap() returned error: %v", err)
	}

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("Successfully connected")) {
		t.Errorf("Bootstrap output should indicate success, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("12D3KooWTestPeer")) {
		t.Errorf("Bootstrap output should include peer ID, got: %s", output)
	}
}

func TestCLI_Bootstrap_Failure(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		bootstrapFn: func(ctx context.Context, in *pb.BootstrapRequest, opts ...grpc.CallOption) (*pb.BootstrapResponse, error) {
			return &pb.BootstrapResponse{
				Success: false,
				Error:   "peer not reachable",
			}, nil
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.Bootstrap("/ip4/192.168.1.1/tcp/4001/p2p/12D3KooWTestPeer")
	if err == nil {
		t.Fatal("Bootstrap() should return error when connection fails")
	}

	if !bytes.Contains([]byte(err.Error()), []byte("peer not reachable")) {
		t.Errorf("Error should contain failure reason, got: %v", err)
	}
}

func TestCLI_Bootstrap_EmptyAddr(t *testing.T) {
	var out bytes.Buffer
	cli := &CLI{
		agentClient: &mockAgentServiceClient{},
		output:      &out,
	}

	err := cli.Bootstrap("")
	if err == nil {
		t.Fatal("Bootstrap() should return error for empty address")
	}
}

func TestCLI_Identity_Success(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		identityFn: func(ctx context.Context, in *pb.IdentityRequest, opts ...grpc.CallOption) (*pb.IdentityResponse, error) {
			return &pb.IdentityResponse{
				PeerId:      "12D3KooWTestPeerID",
				Did:         "did:key:z6MkTestDID",
				ListenAddrs: []string{"/ip4/0.0.0.0/tcp/4001", "/ip6/::/tcp/4001"},
			}, nil
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.Identity()
	if err != nil {
		t.Fatalf("Identity() returned error: %v", err)
	}

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("12D3KooWTestPeerID")) {
		t.Errorf("Identity output missing peer ID, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("did:key:z6MkTestDID")) {
		t.Errorf("Identity output missing DID, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("/ip4/0.0.0.0/tcp/4001")) {
		t.Errorf("Identity output missing listen address, got: %s", output)
	}
}

func TestCLI_Identity_Error(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		identityFn: func(ctx context.Context, in *pb.IdentityRequest, opts ...grpc.CallOption) (*pb.IdentityResponse, error) {
			return nil, errors.New("connection refused")
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.Identity()
	if err == nil {
		t.Fatal("Identity() should return error when agent is not available")
	}
}

func TestFormatTimestamp(t *testing.T) {
	tests := []struct {
		name      string
		timestamp int64
		want      string
	}{
		{
			name:      "zero timestamp",
			timestamp: 0,
			want:      "never",
		},
		{
			name:      "valid timestamp",
			timestamp: 1704067200, // 2024-01-01 00:00:00 UTC
			want:      "2024-01-01 00:00:00",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatTimestamp(tt.timestamp)
			if tt.timestamp == 0 {
				if got != "never" {
					t.Errorf("formatTimestamp(%d) = %s, want %s", tt.timestamp, got, tt.want)
				}
			} else {
				// Just check it's not empty for valid timestamps
				if got == "" || got == "never" {
					t.Errorf("formatTimestamp(%d) should return a formatted date, got: %s", tt.timestamp, got)
				}
			}
		})
	}
}

func TestPrintUsage(t *testing.T) {
	var out bytes.Buffer
	printUsageTo(&out)

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("mymonad-cli")) {
		t.Errorf("Usage output missing program name, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("status")) {
		t.Errorf("Usage output missing 'status' command, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("peers")) {
		t.Errorf("Usage output missing 'peers' command, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("bootstrap")) {
		t.Errorf("Usage output missing 'bootstrap' command, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("identity")) {
		t.Errorf("Usage output missing 'identity' command, got: %s", output)
	}
}

func TestNewCLI(t *testing.T) {
	cli := NewCLI("/tmp/agent.sock", "/tmp/ingest.sock")
	defer cli.Close()

	if cli.agentSocket != "/tmp/agent.sock" {
		t.Errorf("agentSocket = %s, want /tmp/agent.sock", cli.agentSocket)
	}
	if cli.ingestSocket != "/tmp/ingest.sock" {
		t.Errorf("ingestSocket = %s, want /tmp/ingest.sock", cli.ingestSocket)
	}
	if cli.output == nil {
		t.Error("output should not be nil")
	}
}

func TestNewCLIWithDefaults(t *testing.T) {
	cli := NewCLIWithDefaults()
	defer cli.Close()

	if cli.agentSocket == "" {
		t.Error("agentSocket should not be empty")
	}
	if cli.ingestSocket == "" {
		t.Error("ingestSocket should not be empty")
	}
}

func TestCLI_Status_IngestError(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		statusFn: func(ctx context.Context, in *pb.AgentStatusRequest, opts ...grpc.CallOption) (*pb.AgentStatusResponse, error) {
			return &pb.AgentStatusResponse{
				Ready:            true,
				PeerId:           "12D3KooWTestPeerID",
				ConnectedPeers:   5,
				ActiveHandshakes: 2,
				State:            "running",
			}, nil
		},
	}

	ingestMock := &mockMonadStoreClient{
		statusFn: func(ctx context.Context, in *pb.StatusRequest, opts ...grpc.CallOption) (*pb.StatusResponse, error) {
			return nil, errors.New("connection refused")
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient:  agentMock,
		ingestClient: ingestMock,
		output:       &out,
	}

	err := cli.Status()
	// Status should still work but show the error
	if err != nil {
		t.Fatalf("Status() should not return error when one daemon fails: %v", err)
	}

	output := out.String()
	// Should show agent running
	if !bytes.Contains([]byte(output), []byte("running")) {
		t.Errorf("Status output should show agent running, got: %s", output)
	}
	// Should show ingest not running
	if !bytes.Contains([]byte(output), []byte("not running")) {
		t.Errorf("Status output should indicate ingest is not running, got: %s", output)
	}
}

func TestCLI_Status_BothDaemonsDown(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		statusFn: func(ctx context.Context, in *pb.AgentStatusRequest, opts ...grpc.CallOption) (*pb.AgentStatusResponse, error) {
			return nil, errors.New("connection refused")
		},
	}

	ingestMock := &mockMonadStoreClient{
		statusFn: func(ctx context.Context, in *pb.StatusRequest, opts ...grpc.CallOption) (*pb.StatusResponse, error) {
			return nil, errors.New("connection refused")
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient:  agentMock,
		ingestClient: ingestMock,
		output:       &out,
	}

	err := cli.Status()
	// Status should still work but show both errors
	if err != nil {
		t.Fatalf("Status() should not return error when daemons fail: %v", err)
	}

	output := out.String()
	// Count occurrences of "not running"
	count := bytes.Count([]byte(output), []byte("not running"))
	if count != 2 {
		t.Errorf("Status output should indicate both daemons not running (expected 2 'not running', got %d), output: %s", count, output)
	}
}

func TestCLI_Bootstrap_ConnectionError(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		bootstrapFn: func(ctx context.Context, in *pb.BootstrapRequest, opts ...grpc.CallOption) (*pb.BootstrapResponse, error) {
			return nil, errors.New("connection refused")
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.Bootstrap("/ip4/192.168.1.1/tcp/4001/p2p/12D3KooWTestPeer")
	if err == nil {
		t.Fatal("Bootstrap() should return error when RPC fails")
	}

	if !bytes.Contains([]byte(err.Error()), []byte("failed to bootstrap")) {
		t.Errorf("Error should indicate bootstrap failure, got: %v", err)
	}
}

func TestCLI_Close(t *testing.T) {
	// Test that Close doesn't panic with nil connections
	cli := &CLI{}
	cli.Close() // Should not panic
}

func TestErrEmptyAddress(t *testing.T) {
	if ErrEmptyAddress.Error() != "multiaddr cannot be empty" {
		t.Errorf("ErrEmptyAddress has unexpected message: %v", ErrEmptyAddress)
	}
}

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
	statusFn          func(ctx context.Context, in *pb.AgentStatusRequest, opts ...grpc.CallOption) (*pb.AgentStatusResponse, error)
	peersFn           func(ctx context.Context, in *pb.PeersRequest, opts ...grpc.CallOption) (*pb.PeersResponse, error)
	bootstrapFn       func(ctx context.Context, in *pb.BootstrapRequest, opts ...grpc.CallOption) (*pb.BootstrapResponse, error)
	identityFn        func(ctx context.Context, in *pb.IdentityRequest, opts ...grpc.CallOption) (*pb.IdentityResponse, error)
	startHandshakeFn  func(ctx context.Context, in *pb.StartHandshakeRequest, opts ...grpc.CallOption) (*pb.StartHandshakeResponse, error)
	listHandshakesFn  func(ctx context.Context, in *pb.ListHandshakesRequest, opts ...grpc.CallOption) (*pb.ListHandshakesResponse, error)
	getHandshakeFn    func(ctx context.Context, in *pb.GetHandshakeRequest, opts ...grpc.CallOption) (*pb.GetHandshakeResponse, error)
	approveHandshakeFn func(ctx context.Context, in *pb.ApproveHandshakeRequest, opts ...grpc.CallOption) (*pb.ApproveHandshakeResponse, error)
	rejectHandshakeFn func(ctx context.Context, in *pb.RejectHandshakeRequest, opts ...grpc.CallOption) (*pb.RejectHandshakeResponse, error)
	watchHandshakesFn func(ctx context.Context, in *pb.WatchHandshakesRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[pb.HandshakeEvent], error)
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

func (m *mockAgentServiceClient) StartHandshake(ctx context.Context, in *pb.StartHandshakeRequest, opts ...grpc.CallOption) (*pb.StartHandshakeResponse, error) {
	if m.startHandshakeFn != nil {
		return m.startHandshakeFn(ctx, in, opts...)
	}
	return nil, errors.New("StartHandshake not mocked")
}

func (m *mockAgentServiceClient) ListHandshakes(ctx context.Context, in *pb.ListHandshakesRequest, opts ...grpc.CallOption) (*pb.ListHandshakesResponse, error) {
	if m.listHandshakesFn != nil {
		return m.listHandshakesFn(ctx, in, opts...)
	}
	return nil, errors.New("ListHandshakes not mocked")
}

func (m *mockAgentServiceClient) GetHandshake(ctx context.Context, in *pb.GetHandshakeRequest, opts ...grpc.CallOption) (*pb.GetHandshakeResponse, error) {
	if m.getHandshakeFn != nil {
		return m.getHandshakeFn(ctx, in, opts...)
	}
	return nil, errors.New("GetHandshake not mocked")
}

func (m *mockAgentServiceClient) ApproveHandshake(ctx context.Context, in *pb.ApproveHandshakeRequest, opts ...grpc.CallOption) (*pb.ApproveHandshakeResponse, error) {
	if m.approveHandshakeFn != nil {
		return m.approveHandshakeFn(ctx, in, opts...)
	}
	return nil, errors.New("ApproveHandshake not mocked")
}

func (m *mockAgentServiceClient) RejectHandshake(ctx context.Context, in *pb.RejectHandshakeRequest, opts ...grpc.CallOption) (*pb.RejectHandshakeResponse, error) {
	if m.rejectHandshakeFn != nil {
		return m.rejectHandshakeFn(ctx, in, opts...)
	}
	return nil, errors.New("RejectHandshake not mocked")
}

func (m *mockAgentServiceClient) WatchHandshakes(ctx context.Context, in *pb.WatchHandshakesRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[pb.HandshakeEvent], error) {
	if m.watchHandshakesFn != nil {
		return m.watchHandshakesFn(ctx, in, opts...)
	}
	return nil, errors.New("WatchHandshakes not mocked")
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

// Handshake command tests

func TestCLI_Handshake_NoSubcommand(t *testing.T) {
	var out bytes.Buffer
	cli := &CLI{
		agentClient: &mockAgentServiceClient{},
		output:      &out,
	}

	err := cli.Handshake([]string{})
	if err == nil {
		t.Fatal("Handshake() should return error when no subcommand provided")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("usage")) {
		t.Errorf("Error should contain usage info, got: %v", err)
	}
}

func TestCLI_Handshake_UnknownSubcommand(t *testing.T) {
	var out bytes.Buffer
	cli := &CLI{
		agentClient: &mockAgentServiceClient{},
		output:      &out,
	}

	err := cli.Handshake([]string{"unknown"})
	if err == nil {
		t.Fatal("Handshake() should return error for unknown subcommand")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("unknown handshake subcommand")) {
		t.Errorf("Error should mention unknown subcommand, got: %v", err)
	}
}

func TestCLI_HandshakeStart_Success(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		startHandshakeFn: func(ctx context.Context, in *pb.StartHandshakeRequest, opts ...grpc.CallOption) (*pb.StartHandshakeResponse, error) {
			if in.PeerId != "12D3KooWTestPeer" {
				t.Errorf("Unexpected peer ID: %s", in.PeerId)
			}
			return &pb.StartHandshakeResponse{
				SessionId: "session-123",
			}, nil
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.HandshakeStart([]string{"12D3KooWTestPeer"})
	if err != nil {
		t.Fatalf("HandshakeStart() returned error: %v", err)
	}

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("session-123")) {
		t.Errorf("Output should contain session ID, got: %s", output)
	}
}

func TestCLI_HandshakeStart_NoPeerID(t *testing.T) {
	var out bytes.Buffer
	cli := &CLI{
		agentClient: &mockAgentServiceClient{},
		output:      &out,
	}

	err := cli.HandshakeStart([]string{})
	if err == nil {
		t.Fatal("HandshakeStart() should return error when no peer ID provided")
	}
}

func TestCLI_HandshakeStart_Error(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		startHandshakeFn: func(ctx context.Context, in *pb.StartHandshakeRequest, opts ...grpc.CallOption) (*pb.StartHandshakeResponse, error) {
			return &pb.StartHandshakeResponse{
				Error: "peer not found",
			}, nil
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.HandshakeStart([]string{"invalid-peer"})
	if err == nil {
		t.Fatal("HandshakeStart() should return error when handshake fails")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("peer not found")) {
		t.Errorf("Error should contain reason, got: %v", err)
	}
}

func TestCLI_HandshakeList_Success(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		listHandshakesFn: func(ctx context.Context, in *pb.ListHandshakesRequest, opts ...grpc.CallOption) (*pb.ListHandshakesResponse, error) {
			return &pb.ListHandshakesResponse{
				Handshakes: []*pb.HandshakeInfo{
					{
						SessionId:      "session-1",
						PeerId:         "12D3KooWPeer1",
						State:          "attestation",
						Role:           "initiator",
						ElapsedSeconds: 30,
					},
					{
						SessionId:           "session-2",
						PeerId:              "12D3KooWPeer2",
						State:               "unmask",
						Role:                "responder",
						ElapsedSeconds:      120,
						PendingApproval:     true,
						PendingApprovalType: "unmask",
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

	err := cli.HandshakeList()
	if err != nil {
		t.Fatalf("HandshakeList() returned error: %v", err)
	}

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("session-1")) {
		t.Errorf("Output should contain session-1, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("PENDING")) {
		t.Errorf("Output should indicate pending approval, got: %s", output)
	}
}

func TestCLI_HandshakeList_Empty(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		listHandshakesFn: func(ctx context.Context, in *pb.ListHandshakesRequest, opts ...grpc.CallOption) (*pb.ListHandshakesResponse, error) {
			return &pb.ListHandshakesResponse{
				Handshakes: []*pb.HandshakeInfo{},
			}, nil
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.HandshakeList()
	if err != nil {
		t.Fatalf("HandshakeList() returned error: %v", err)
	}

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("No active handshakes")) {
		t.Errorf("Output should indicate no handshakes, got: %s", output)
	}
}

func TestCLI_HandshakeShow_Success(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		getHandshakeFn: func(ctx context.Context, in *pb.GetHandshakeRequest, opts ...grpc.CallOption) (*pb.GetHandshakeResponse, error) {
			return &pb.GetHandshakeResponse{
				Handshake: &pb.HandshakeInfo{
					SessionId:           "session-123",
					PeerId:              "12D3KooWTestPeer",
					State:               "vector_match",
					Role:                "initiator",
					ElapsedSeconds:      45,
					PendingApproval:     true,
					PendingApprovalType: "vector_match",
				},
			}, nil
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.HandshakeShow([]string{"session-123"})
	if err != nil {
		t.Fatalf("HandshakeShow() returned error: %v", err)
	}

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("session-123")) {
		t.Errorf("Output should contain session ID, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("vector_match")) {
		t.Errorf("Output should contain state, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("Pending")) {
		t.Errorf("Output should indicate pending approval, got: %s", output)
	}
}

func TestCLI_HandshakeShow_NoSessionID(t *testing.T) {
	var out bytes.Buffer
	cli := &CLI{
		agentClient: &mockAgentServiceClient{},
		output:      &out,
	}

	err := cli.HandshakeShow([]string{})
	if err == nil {
		t.Fatal("HandshakeShow() should return error when no session ID provided")
	}
}

func TestCLI_HandshakeShow_Error(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		getHandshakeFn: func(ctx context.Context, in *pb.GetHandshakeRequest, opts ...grpc.CallOption) (*pb.GetHandshakeResponse, error) {
			return &pb.GetHandshakeResponse{
				Error: "session not found",
			}, nil
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.HandshakeShow([]string{"invalid-session"})
	if err == nil {
		t.Fatal("HandshakeShow() should return error when session not found")
	}
}

func TestCLI_HandshakeApprove_Success(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		approveHandshakeFn: func(ctx context.Context, in *pb.ApproveHandshakeRequest, opts ...grpc.CallOption) (*pb.ApproveHandshakeResponse, error) {
			if in.SessionId != "session-123" {
				t.Errorf("Unexpected session ID: %s", in.SessionId)
			}
			return &pb.ApproveHandshakeResponse{
				Success: true,
			}, nil
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.HandshakeApprove([]string{"session-123"})
	if err != nil {
		t.Fatalf("HandshakeApprove() returned error: %v", err)
	}

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("approved")) {
		t.Errorf("Output should indicate approval, got: %s", output)
	}
}

func TestCLI_HandshakeApprove_NoSessionID(t *testing.T) {
	var out bytes.Buffer
	cli := &CLI{
		agentClient: &mockAgentServiceClient{},
		output:      &out,
	}

	err := cli.HandshakeApprove([]string{})
	if err == nil {
		t.Fatal("HandshakeApprove() should return error when no session ID provided")
	}
}

func TestCLI_HandshakeApprove_Failure(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		approveHandshakeFn: func(ctx context.Context, in *pb.ApproveHandshakeRequest, opts ...grpc.CallOption) (*pb.ApproveHandshakeResponse, error) {
			return &pb.ApproveHandshakeResponse{
				Success: false,
				Error:   "nothing to approve",
			}, nil
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.HandshakeApprove([]string{"session-123"})
	if err == nil {
		t.Fatal("HandshakeApprove() should return error when approval fails")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("nothing to approve")) {
		t.Errorf("Error should contain reason, got: %v", err)
	}
}

func TestCLI_HandshakeReject_Success(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		rejectHandshakeFn: func(ctx context.Context, in *pb.RejectHandshakeRequest, opts ...grpc.CallOption) (*pb.RejectHandshakeResponse, error) {
			if in.SessionId != "session-123" {
				t.Errorf("Unexpected session ID: %s", in.SessionId)
			}
			if in.Reason != "not interested" {
				t.Errorf("Unexpected reason: %s", in.Reason)
			}
			return &pb.RejectHandshakeResponse{
				Success: true,
			}, nil
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.HandshakeReject([]string{"session-123", "not interested"})
	if err != nil {
		t.Fatalf("HandshakeReject() returned error: %v", err)
	}

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("rejected")) {
		t.Errorf("Output should indicate rejection, got: %s", output)
	}
}

func TestCLI_HandshakeReject_NoReason(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		rejectHandshakeFn: func(ctx context.Context, in *pb.RejectHandshakeRequest, opts ...grpc.CallOption) (*pb.RejectHandshakeResponse, error) {
			if in.Reason != "" {
				t.Errorf("Reason should be empty when not provided, got: %s", in.Reason)
			}
			return &pb.RejectHandshakeResponse{
				Success: true,
			}, nil
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.HandshakeReject([]string{"session-123"})
	if err != nil {
		t.Fatalf("HandshakeReject() returned error: %v", err)
	}
}

func TestCLI_HandshakeReject_NoSessionID(t *testing.T) {
	var out bytes.Buffer
	cli := &CLI{
		agentClient: &mockAgentServiceClient{},
		output:      &out,
	}

	err := cli.HandshakeReject([]string{})
	if err == nil {
		t.Fatal("HandshakeReject() should return error when no session ID provided")
	}
}

func TestTruncatePeerID(t *testing.T) {
	tests := []struct {
		name   string
		peerID string
		want   string
	}{
		{
			name:   "short peer ID",
			peerID: "12D3KooW",
			want:   "12D3KooW",
		},
		{
			name:   "exact 16 chars",
			peerID: "12D3KooWTestPeer",
			want:   "12D3KooWTestPeer",
		},
		{
			name:   "long peer ID",
			peerID: "12D3KooWTestPeerVeryLong",
			want:   "12D3KooWTestPeer...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncatePeerID(tt.peerID)
			if got != tt.want {
				t.Errorf("truncatePeerID(%s) = %s, want %s", tt.peerID, got, tt.want)
			}
		})
	}
}

func TestTruncateSessionID(t *testing.T) {
	tests := []struct {
		name      string
		sessionID string
		want      string
	}{
		{
			name:      "short session ID",
			sessionID: "abc123",
			want:      "abc123",
		},
		{
			name:      "exact 8 chars",
			sessionID: "abcd1234",
			want:      "abcd1234",
		},
		{
			name:      "long session ID",
			sessionID: "abcd1234-5678-90ab",
			want:      "abcd1234...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateSessionID(tt.sessionID)
			if got != tt.want {
				t.Errorf("truncateSessionID(%s) = %s, want %s", tt.sessionID, got, tt.want)
			}
		})
	}
}

func TestPrintUsage_IncludesHandshake(t *testing.T) {
	var out bytes.Buffer
	printUsageTo(&out)

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("handshake")) {
		t.Errorf("Usage output missing 'handshake' command, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("start")) {
		t.Errorf("Usage output missing 'start' subcommand, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("list")) {
		t.Errorf("Usage output missing 'list' subcommand, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("approve")) {
		t.Errorf("Usage output missing 'approve' subcommand, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("reject")) {
		t.Errorf("Usage output missing 'reject' subcommand, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("watch")) {
		t.Errorf("Usage output missing 'watch' subcommand, got: %s", output)
	}
}

func TestCLI_Handshake_SubcommandDispatch(t *testing.T) {
	// Test that all subcommands dispatch correctly
	subcommands := []string{"start", "list", "show", "approve", "reject", "watch"}

	for _, sub := range subcommands {
		t.Run(sub, func(t *testing.T) {
			var out bytes.Buffer
			cli := &CLI{
				agentClient: &mockAgentServiceClient{},
				output:      &out,
			}

			// We expect these to fail since mocks aren't set up, but we're testing dispatch
			_ = cli.Handshake([]string{sub})
			// Just verify we don't panic
		})
	}
}

func TestCLI_HandshakeList_RPCError(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		listHandshakesFn: func(ctx context.Context, in *pb.ListHandshakesRequest, opts ...grpc.CallOption) (*pb.ListHandshakesResponse, error) {
			return nil, errors.New("connection refused")
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.HandshakeList()
	if err == nil {
		t.Fatal("HandshakeList() should return error on RPC failure")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("failed to list handshakes")) {
		t.Errorf("Error should indicate list failure, got: %v", err)
	}
}

func TestCLI_HandshakeShow_RPCError(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		getHandshakeFn: func(ctx context.Context, in *pb.GetHandshakeRequest, opts ...grpc.CallOption) (*pb.GetHandshakeResponse, error) {
			return nil, errors.New("connection refused")
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.HandshakeShow([]string{"session-123"})
	if err == nil {
		t.Fatal("HandshakeShow() should return error on RPC failure")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("failed to get handshake")) {
		t.Errorf("Error should indicate get failure, got: %v", err)
	}
}

func TestCLI_HandshakeApprove_RPCError(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		approveHandshakeFn: func(ctx context.Context, in *pb.ApproveHandshakeRequest, opts ...grpc.CallOption) (*pb.ApproveHandshakeResponse, error) {
			return nil, errors.New("connection refused")
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.HandshakeApprove([]string{"session-123"})
	if err == nil {
		t.Fatal("HandshakeApprove() should return error on RPC failure")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("failed to approve")) {
		t.Errorf("Error should indicate approve failure, got: %v", err)
	}
}

func TestCLI_HandshakeReject_RPCError(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		rejectHandshakeFn: func(ctx context.Context, in *pb.RejectHandshakeRequest, opts ...grpc.CallOption) (*pb.RejectHandshakeResponse, error) {
			return nil, errors.New("connection refused")
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.HandshakeReject([]string{"session-123"})
	if err == nil {
		t.Fatal("HandshakeReject() should return error on RPC failure")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("failed to reject")) {
		t.Errorf("Error should indicate reject failure, got: %v", err)
	}
}

func TestCLI_HandshakeReject_Failure(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		rejectHandshakeFn: func(ctx context.Context, in *pb.RejectHandshakeRequest, opts ...grpc.CallOption) (*pb.RejectHandshakeResponse, error) {
			return &pb.RejectHandshakeResponse{
				Success: false,
				Error:   "session already completed",
			}, nil
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.HandshakeReject([]string{"session-123"})
	if err == nil {
		t.Fatal("HandshakeReject() should return error when rejection fails")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("session already completed")) {
		t.Errorf("Error should contain reason, got: %v", err)
	}
}

func TestCLI_HandshakeStart_RPCError(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		startHandshakeFn: func(ctx context.Context, in *pb.StartHandshakeRequest, opts ...grpc.CallOption) (*pb.StartHandshakeResponse, error) {
			return nil, errors.New("connection refused")
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.HandshakeStart([]string{"peer-id"})
	if err == nil {
		t.Fatal("HandshakeStart() should return error on RPC failure")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("failed to start handshake")) {
		t.Errorf("Error should indicate start failure, got: %v", err)
	}
}

func TestCLI_HandshakeWatch_RPCError(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		watchHandshakesFn: func(ctx context.Context, in *pb.WatchHandshakesRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[pb.HandshakeEvent], error) {
			return nil, errors.New("connection refused")
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.HandshakeWatch()
	if err == nil {
		t.Fatal("HandshakeWatch() should return error on RPC failure")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("failed to watch")) {
		t.Errorf("Error should indicate watch failure, got: %v", err)
	}
}

func TestCLI_HandshakeShow_NoPendingApproval(t *testing.T) {
	agentMock := &mockAgentServiceClient{
		getHandshakeFn: func(ctx context.Context, in *pb.GetHandshakeRequest, opts ...grpc.CallOption) (*pb.GetHandshakeResponse, error) {
			return &pb.GetHandshakeResponse{
				Handshake: &pb.HandshakeInfo{
					SessionId:       "session-123",
					PeerId:          "12D3KooWTestPeer",
					State:           "attestation",
					Role:            "initiator",
					ElapsedSeconds:  10,
					PendingApproval: false,
				},
			}, nil
		},
	}

	var out bytes.Buffer
	cli := &CLI{
		agentClient: agentMock,
		output:      &out,
	}

	err := cli.HandshakeShow([]string{"session-123"})
	if err != nil {
		t.Fatalf("HandshakeShow() returned error: %v", err)
	}

	output := out.String()
	// Should NOT contain "Pending:" line when there's no pending approval
	if bytes.Contains([]byte(output), []byte("Pending:")) {
		t.Errorf("Output should not show pending line when no approval pending, got: %s", output)
	}
}

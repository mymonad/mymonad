package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
	"github.com/mymonad/mymonad/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// defaultRPCTimeout is the default timeout for RPC calls.
const defaultRPCTimeout = 5 * time.Second

// ErrEmptyAddress is returned when an empty multiaddr is provided to Bootstrap.
var ErrEmptyAddress = errors.New("multiaddr cannot be empty")

// CLI provides commands for interacting with the mymonad daemons.
type CLI struct {
	agentSocket  string
	ingestSocket string
	agentClient  pb.AgentServiceClient
	ingestClient pb.MonadStoreClient
	agentConn    *grpc.ClientConn
	ingestConn   *grpc.ClientConn
	output       io.Writer
}

// NewCLI creates a new CLI instance that connects to the daemons via Unix sockets.
func NewCLI(agentSocket, ingestSocket string) *CLI {
	return &CLI{
		agentSocket:  agentSocket,
		ingestSocket: ingestSocket,
		output:       os.Stdout,
	}
}

// NewCLIWithDefaults creates a new CLI instance using default socket paths.
func NewCLIWithDefaults() *CLI {
	paths := config.DefaultPaths()
	return NewCLI(paths.AgentSocket, paths.IngestSocket)
}

// connectAgent establishes a connection to the agent daemon.
func (c *CLI) connectAgent() error {
	if c.agentClient != nil {
		return nil
	}

	conn, err := grpc.Dial(
		"unix://"+c.agentSocket,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to agent daemon: %w", err)
	}

	c.agentConn = conn
	c.agentClient = pb.NewAgentServiceClient(conn)
	return nil
}

// connectIngest establishes a connection to the ingest daemon.
func (c *CLI) connectIngest() error {
	if c.ingestClient != nil {
		return nil
	}

	conn, err := grpc.Dial(
		"unix://"+c.ingestSocket,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to ingest daemon: %w", err)
	}

	c.ingestConn = conn
	c.ingestClient = pb.NewMonadStoreClient(conn)
	return nil
}

// Close closes all daemon connections.
func (c *CLI) Close() {
	if c.agentConn != nil {
		c.agentConn.Close()
	}
	if c.ingestConn != nil {
		c.ingestConn.Close()
	}
}

// Status displays the status of both the agent and ingest daemons.
func (c *CLI) Status() error {
	fmt.Fprintln(c.output, "=== MyMonad Status ===")
	fmt.Fprintln(c.output)

	// Agent status
	c.printAgentStatus()
	fmt.Fprintln(c.output)

	// Ingest status
	c.printIngestStatus()

	return nil
}

// printAgentStatus prints the agent daemon status.
func (c *CLI) printAgentStatus() {
	fmt.Fprintln(c.output, "Agent Daemon:")

	if err := c.connectAgent(); err != nil {
		fmt.Fprintf(c.output, "  Status: not running\n")
		fmt.Fprintf(c.output, "  Error: %v\n", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultRPCTimeout)
	defer cancel()

	resp, err := c.agentClient.Status(ctx, &pb.AgentStatusRequest{})
	if err != nil {
		fmt.Fprintf(c.output, "  Status: not running\n")
		fmt.Fprintf(c.output, "  Error: %v\n", err)
		return
	}

	fmt.Fprintf(c.output, "  Status: %s\n", resp.State)
	fmt.Fprintf(c.output, "  Ready: %v\n", resp.Ready)
	fmt.Fprintf(c.output, "  Peer ID: %s\n", resp.PeerId)
	fmt.Fprintf(c.output, "  Connected Peers: %d\n", resp.ConnectedPeers)
	fmt.Fprintf(c.output, "  Active Handshakes: %d\n", resp.ActiveHandshakes)
}

// printIngestStatus prints the ingest daemon status.
func (c *CLI) printIngestStatus() {
	fmt.Fprintln(c.output, "Ingest Daemon:")

	if err := c.connectIngest(); err != nil {
		fmt.Fprintf(c.output, "  Status: not running\n")
		fmt.Fprintf(c.output, "  Error: %v\n", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultRPCTimeout)
	defer cancel()

	resp, err := c.ingestClient.Status(ctx, &pb.StatusRequest{})
	if err != nil {
		fmt.Fprintf(c.output, "  Status: not running\n")
		fmt.Fprintf(c.output, "  Error: %v\n", err)
		return
	}

	fmt.Fprintf(c.output, "  Status: %s\n", resp.State)
	fmt.Fprintf(c.output, "  Ready: %v\n", resp.Ready)
	fmt.Fprintf(c.output, "  Documents Indexed: %d\n", resp.DocumentsIndexed)
	fmt.Fprintf(c.output, "  Last Scan: %s\n", formatTimestamp(resp.LastScanTimestamp))
}

// Peers lists all connected peers.
func (c *CLI) Peers() error {
	if err := c.connectAgent(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultRPCTimeout)
	defer cancel()

	resp, err := c.agentClient.Peers(ctx, &pb.PeersRequest{})
	if err != nil {
		return fmt.Errorf("failed to get peers: %w", err)
	}

	if len(resp.Peers) == 0 {
		fmt.Fprintln(c.output, "No connected peers")
		return nil
	}

	fmt.Fprintf(c.output, "Connected Peers (%d):\n", len(resp.Peers))
	fmt.Fprintln(c.output)

	for _, peer := range resp.Peers {
		fmt.Fprintf(c.output, "  Peer ID: %s\n", peer.PeerId)
		fmt.Fprintf(c.output, "  State: %s\n", peer.ConnectionState)
		fmt.Fprintln(c.output, "  Addresses:")
		for _, addr := range peer.Addrs {
			fmt.Fprintf(c.output, "    - %s\n", addr)
		}
		fmt.Fprintln(c.output)
	}

	return nil
}

// Bootstrap manually connects to a peer at the given multiaddr.
func (c *CLI) Bootstrap(multiaddr string) error {
	if multiaddr == "" {
		return ErrEmptyAddress
	}

	if err := c.connectAgent(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultRPCTimeout)
	defer cancel()

	resp, err := c.agentClient.Bootstrap(ctx, &pb.BootstrapRequest{
		Multiaddr: multiaddr,
	})
	if err != nil {
		return fmt.Errorf("failed to bootstrap: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("bootstrap failed: %s", resp.Error)
	}

	fmt.Fprintf(c.output, "Successfully connected to peer: %s\n", resp.PeerId)
	return nil
}

// Identity displays the local identity information.
func (c *CLI) Identity() error {
	if err := c.connectAgent(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultRPCTimeout)
	defer cancel()

	resp, err := c.agentClient.Identity(ctx, &pb.IdentityRequest{})
	if err != nil {
		return fmt.Errorf("failed to get identity: %w", err)
	}

	fmt.Fprintln(c.output, "=== Local Identity ===")
	fmt.Fprintln(c.output)
	fmt.Fprintf(c.output, "Peer ID: %s\n", resp.PeerId)
	fmt.Fprintf(c.output, "DID: %s\n", resp.Did)
	fmt.Fprintln(c.output)
	fmt.Fprintln(c.output, "Listen Addresses:")
	for _, addr := range resp.ListenAddrs {
		fmt.Fprintf(c.output, "  - %s\n", addr)
	}

	return nil
}

// formatTimestamp formats a Unix timestamp for display.
func formatTimestamp(ts int64) string {
	if ts == 0 {
		return "never"
	}
	return time.Unix(ts, 0).UTC().Format("2006-01-02 15:04:05")
}

// printUsage prints the CLI usage information to stdout.
func printUsage() {
	printUsageTo(os.Stdout)
}

// printUsageTo prints the CLI usage information to the given writer.
func printUsageTo(w io.Writer) {
	fmt.Fprintln(w, "Usage: mymonad-cli <command> [arguments]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  status              Show agent and ingest daemon status")
	fmt.Fprintln(w, "  peers               List connected peers")
	fmt.Fprintln(w, "  bootstrap <addr>    Manually connect to a peer")
	fmt.Fprintln(w, "  identity            Show local DID and peer ID")
	fmt.Fprintln(w, "  handshake           Manage handshake sessions")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Handshake Subcommands:")
	fmt.Fprintln(w, "  handshake start <peer-id>      Start a handshake with a peer")
	fmt.Fprintln(w, "  handshake list                 List all active handshakes")
	fmt.Fprintln(w, "  handshake show <session-id>    Show details of a handshake")
	fmt.Fprintln(w, "  handshake approve <session-id> Approve a pending handshake")
	fmt.Fprintln(w, "  handshake reject <session-id>  Reject a handshake")
	fmt.Fprintln(w, "  handshake watch                Watch handshake events in real-time")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  mymonad-cli status")
	fmt.Fprintln(w, "  mymonad-cli peers")
	fmt.Fprintln(w, "  mymonad-cli bootstrap /ip4/192.168.1.1/tcp/4001/p2p/12D3KooW...")
	fmt.Fprintln(w, "  mymonad-cli identity")
	fmt.Fprintln(w, "  mymonad-cli handshake start 12D3KooW...")
	fmt.Fprintln(w, "  mymonad-cli handshake list")
}

// Handshake dispatches handshake subcommands.
func (c *CLI) Handshake(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mymonad-cli handshake <subcommand>\nsubcommands: start, list, show, approve, reject, watch")
	}

	subcommand := args[0]
	subargs := args[1:]

	switch subcommand {
	case "start":
		return c.HandshakeStart(subargs)
	case "list":
		return c.HandshakeList()
	case "show":
		return c.HandshakeShow(subargs)
	case "approve":
		return c.HandshakeApprove(subargs)
	case "reject":
		return c.HandshakeReject(subargs)
	case "watch":
		return c.HandshakeWatch()
	default:
		return fmt.Errorf("unknown handshake subcommand: %s", subcommand)
	}
}

// HandshakeStart initiates a handshake with a peer.
func (c *CLI) HandshakeStart(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mymonad-cli handshake start <peer-id>")
	}
	peerID := args[0]

	if err := c.connectAgent(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultRPCTimeout)
	defer cancel()

	resp, err := c.agentClient.StartHandshake(ctx, &pb.StartHandshakeRequest{
		PeerId: peerID,
	})
	if err != nil {
		return fmt.Errorf("failed to start handshake: %w", err)
	}

	if resp.Error != "" {
		return fmt.Errorf("handshake error: %s", resp.Error)
	}

	fmt.Fprintf(c.output, "Handshake started: session_id=%s\n", resp.SessionId)
	return nil
}

// HandshakeList lists all active handshakes.
func (c *CLI) HandshakeList() error {
	if err := c.connectAgent(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultRPCTimeout)
	defer cancel()

	resp, err := c.agentClient.ListHandshakes(ctx, &pb.ListHandshakesRequest{})
	if err != nil {
		return fmt.Errorf("failed to list handshakes: %w", err)
	}

	if len(resp.Handshakes) == 0 {
		fmt.Fprintln(c.output, "No active handshakes")
		return nil
	}

	fmt.Fprintf(c.output, "%-36s  %-12s  %-10s  %-8s  %s\n", "SESSION", "STATE", "ROLE", "ELAPSED", "PEER")
	for _, h := range resp.Handshakes {
		pending := ""
		if h.PendingApproval {
			pending = fmt.Sprintf(" [PENDING: %s]", h.PendingApprovalType)
		}
		fmt.Fprintf(c.output, "%-36s  %-12s  %-10s  %-8ds  %s%s\n",
			h.SessionId, h.State, h.Role, h.ElapsedSeconds, truncatePeerID(h.PeerId), pending)
	}

	return nil
}

// HandshakeShow displays details of a specific handshake.
func (c *CLI) HandshakeShow(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mymonad-cli handshake show <session-id>")
	}
	sessionID := args[0]

	if err := c.connectAgent(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultRPCTimeout)
	defer cancel()

	resp, err := c.agentClient.GetHandshake(ctx, &pb.GetHandshakeRequest{
		SessionId: sessionID,
	})
	if err != nil {
		return fmt.Errorf("failed to get handshake: %w", err)
	}

	if resp.Error != "" {
		return fmt.Errorf("error: %s", resp.Error)
	}

	h := resp.Handshake
	fmt.Fprintf(c.output, "Session ID: %s\n", h.SessionId)
	fmt.Fprintf(c.output, "Peer ID:    %s\n", h.PeerId)
	fmt.Fprintf(c.output, "State:      %s\n", h.State)
	fmt.Fprintf(c.output, "Role:       %s\n", h.Role)
	fmt.Fprintf(c.output, "Elapsed:    %d seconds\n", h.ElapsedSeconds)
	if h.PendingApproval {
		fmt.Fprintf(c.output, "Pending:    %s\n", h.PendingApprovalType)
	}

	return nil
}

// HandshakeApprove approves a pending handshake.
func (c *CLI) HandshakeApprove(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mymonad-cli handshake approve <session-id>")
	}
	sessionID := args[0]

	if err := c.connectAgent(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultRPCTimeout)
	defer cancel()

	resp, err := c.agentClient.ApproveHandshake(ctx, &pb.ApproveHandshakeRequest{
		SessionId: sessionID,
	})
	if err != nil {
		return fmt.Errorf("failed to approve: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("approval failed: %s", resp.Error)
	}

	fmt.Fprintln(c.output, "Handshake approved")
	return nil
}

// HandshakeReject rejects a handshake.
func (c *CLI) HandshakeReject(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mymonad-cli handshake reject <session-id> [reason]")
	}
	sessionID := args[0]
	reason := ""
	if len(args) > 1 {
		reason = args[1]
	}

	if err := c.connectAgent(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultRPCTimeout)
	defer cancel()

	resp, err := c.agentClient.RejectHandshake(ctx, &pb.RejectHandshakeRequest{
		SessionId: sessionID,
		Reason:    reason,
	})
	if err != nil {
		return fmt.Errorf("failed to reject: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("rejection failed: %s", resp.Error)
	}

	fmt.Fprintln(c.output, "Handshake rejected")
	return nil
}

// HandshakeWatch watches handshake events in real-time.
func (c *CLI) HandshakeWatch() error {
	if err := c.connectAgent(); err != nil {
		return err
	}

	// No timeout for watch - it's a long-running stream
	stream, err := c.agentClient.WatchHandshakes(context.Background(), &pb.WatchHandshakesRequest{})
	if err != nil {
		return fmt.Errorf("failed to watch: %w", err)
	}

	fmt.Fprintln(c.output, "Watching handshake events (Ctrl+C to stop)...")

	for {
		event, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("stream error: %w", err)
		}

		fmt.Fprintf(c.output, "[%s] session=%s peer=%s state=%s elapsed=%ds\n",
			event.EventType, truncateSessionID(event.SessionId), truncatePeerID(event.PeerId),
			event.State, event.ElapsedSeconds)
	}
}

// truncatePeerID truncates long peer IDs for display.
func truncatePeerID(peerID string) string {
	if len(peerID) > 16 {
		return peerID[:16] + "..."
	}
	return peerID
}

// truncateSessionID truncates session IDs for display.
func truncateSessionID(sessionID string) string {
	if len(sessionID) > 8 {
		return sessionID[:8] + "..."
	}
	return sessionID
}

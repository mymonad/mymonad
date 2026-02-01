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
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  mymonad-cli status")
	fmt.Fprintln(w, "  mymonad-cli peers")
	fmt.Fprintln(w, "  mymonad-cli bootstrap /ip4/192.168.1.1/tcp/4001/p2p/12D3KooW...")
	fmt.Fprintln(w, "  mymonad-cli identity")
}

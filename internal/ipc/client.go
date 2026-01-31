package ipc

import (
	"context"
	"errors"
	"fmt"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// defaultRPCTimeout is the default timeout for RPC calls.
const defaultRPCTimeout = 5 * time.Second

// ErrEmptySocketPath is returned when an empty socket path is provided.
var ErrEmptySocketPath = errors.New("socket path cannot be empty")

// Client is the IPC client for connecting to the Ingestion Daemon.
type Client struct {
	conn   *grpc.ClientConn
	client pb.MonadStoreClient
}

// NewClient creates a new IPC client that connects to the Ingestion Daemon
// via a Unix socket at the specified path.
func NewClient(sockPath string) (*Client, error) {
	if sockPath == "" {
		return nil, ErrEmptySocketPath
	}

	conn, err := grpc.Dial(
		"unix://"+sockPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to IPC socket: %w", err)
	}

	return &Client{
		conn:   conn,
		client: pb.NewMonadStoreClient(conn),
	}, nil
}

// Close closes the connection to the Ingestion Daemon.
func (c *Client) Close() error {
	return c.conn.Close()
}

// GetMonad retrieves the current encrypted Monad from the Ingestion Daemon.
// Returns the encrypted monad data, version number, and any error.
func (c *Client) GetMonad() ([]byte, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultRPCTimeout)
	defer cancel()

	resp, err := c.client.GetMonad(ctx, &pb.GetMonadRequest{})
	if err != nil {
		return nil, 0, fmt.Errorf("GetMonad RPC failed: %w", err)
	}
	if resp == nil {
		return nil, 0, fmt.Errorf("GetMonad RPC returned nil response")
	}

	return resp.EncryptedMonad, resp.Version, nil
}

// Status retrieves the Ingestion Daemon status.
// Returns ready state, documents indexed count, current state string, and any error.
func (c *Client) Status() (ready bool, docsIndexed int64, state string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultRPCTimeout)
	defer cancel()

	resp, err := c.client.Status(ctx, &pb.StatusRequest{})
	if err != nil {
		return false, 0, "", fmt.Errorf("Status RPC failed: %w", err)
	}
	if resp == nil {
		return false, 0, "", fmt.Errorf("Status RPC returned nil response")
	}

	return resp.Ready, resp.DocumentsIndexed, resp.State, nil
}

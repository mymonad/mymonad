package ipc

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// waitForServer attempts to connect to the server with retries.
// Returns the connection on success, or fails the test after maxRetries.
func waitForServer(t *testing.T, sockPath string, maxRetries int) *grpc.ClientConn {
	t.Helper()

	var conn *grpc.ClientConn
	var err error

	for i := 0; i < maxRetries; i++ {
		conn, err = grpc.Dial(
			"unix://"+sockPath,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
			grpc.WithTimeout(100*time.Millisecond),
		)
		if err == nil {
			return conn
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("Failed to connect to server after %d retries: %v", maxRetries, err)
	return nil
}

// waitForSocket waits for the socket file to exist with retries.
func waitForSocket(t *testing.T, sockPath string, maxRetries int) {
	t.Helper()

	for i := 0; i < maxRetries; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("Socket file %s did not appear after %d retries", sockPath, maxRetries)
}

func TestServerStartStop(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	store := &MockMonadStore{
		monad:   []byte("test-monad"),
		version: 1,
	}

	server, err := NewServer(sockPath, store)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Start in background
	go server.Start()

	// Wait for socket to exist with retries
	waitForSocket(t, sockPath, 20)

	// Stop
	server.Stop()
}

func TestServerGetMonad(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	expectedMonad := []byte("encrypted-monad-data")
	store := &MockMonadStore{
		monad:   expectedMonad,
		version: 42,
	}

	server, _ := NewServer(sockPath, store)
	go server.Start()
	defer server.Stop()

	// Connect as client with retries
	conn := waitForServer(t, sockPath, 20)
	defer conn.Close()

	client := pb.NewMonadStoreClient(conn)
	resp, err := client.GetMonad(context.Background(), &pb.GetMonadRequest{})
	if err != nil {
		t.Fatalf("GetMonad failed: %v", err)
	}

	if !bytes.Equal(resp.EncryptedMonad, expectedMonad) {
		t.Errorf("Monad mismatch: got %v, want %v", resp.EncryptedMonad, expectedMonad)
	}
	if resp.Version != 42 {
		t.Errorf("Version mismatch: got %d, want 42", resp.Version)
	}
}

func TestServerStatus(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	store := &MockMonadStore{
		monad:   []byte("test-monad"),
		version: 1,
	}

	server, _ := NewServer(sockPath, store)
	go server.Start()
	defer server.Stop()

	// Connect as client with retries
	conn := waitForServer(t, sockPath, 20)
	defer conn.Close()

	client := pb.NewMonadStoreClient(conn)
	resp, err := client.Status(context.Background(), &pb.StatusRequest{})
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}

	if !resp.Ready {
		t.Error("Expected Ready to be true")
	}
	if resp.DocumentsIndexed != 100 {
		t.Errorf("DocumentsIndexed mismatch: got %d, want 100", resp.DocumentsIndexed)
	}
	if resp.State != "idle" {
		t.Errorf("State mismatch: got %s, want idle", resp.State)
	}
}

// MockMonadStore implements MonadProvider for testing.
type MockMonadStore struct {
	monad   []byte
	version int64
}

func (m *MockMonadStore) GetMonad() ([]byte, int64, error) {
	return m.monad, m.version, nil
}

func (m *MockMonadStore) GetStatus() (bool, int64, string) {
	return true, 100, "idle"
}

func TestClient(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	expectedMonad := []byte("client-test-monad")
	store := &MockMonadStore{
		monad:   expectedMonad,
		version: 99,
	}

	server, _ := NewServer(sockPath, store)
	go server.Start()
	defer server.Stop()

	// Wait for socket to be ready
	waitForSocket(t, sockPath, 20)

	// Use our Client wrapper
	client, err := NewClient(sockPath)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	monad, version, err := client.GetMonad()
	if err != nil {
		t.Fatalf("GetMonad failed: %v", err)
	}

	if !bytes.Equal(monad, expectedMonad) {
		t.Errorf("Monad mismatch: got %v, want %v", monad, expectedMonad)
	}
	if version != 99 {
		t.Errorf("Version mismatch: got %d, want 99", version)
	}
}

func TestClientStatus(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	store := &MockMonadStore{
		monad:   []byte("test-monad"),
		version: 1,
	}

	server, _ := NewServer(sockPath, store)
	go server.Start()
	defer server.Stop()

	// Wait for socket to be ready
	waitForSocket(t, sockPath, 20)

	// Use our Client wrapper
	client, err := NewClient(sockPath)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	ready, docsIndexed, state, err := client.Status()
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}

	if !ready {
		t.Error("Expected Ready to be true")
	}
	if docsIndexed != 100 {
		t.Errorf("DocumentsIndexed mismatch: got %d, want 100", docsIndexed)
	}
	if state != "idle" {
		t.Errorf("State mismatch: got %s, want idle", state)
	}
}

func TestClientConnectionFailure(t *testing.T) {
	// Test empty socket path validation
	_, err := NewClient("")
	if err != ErrEmptySocketPath {
		t.Errorf("Expected ErrEmptySocketPath for empty path, got: %v", err)
	}

	// Try to connect to a non-existent socket and verify RPC fails
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "nonexistent.sock")

	client, err := NewClient(sockPath)
	if err != nil {
		// If we get an immediate error, that's acceptable
		return
	}
	defer client.Close()

	// gRPC uses lazy connection, so the error will occur when we try to make an RPC call
	_, _, err = client.GetMonad()
	if err == nil {
		t.Error("Expected error when calling GetMonad on non-existent socket, got nil")
	}
}

func TestClientClose(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	store := &MockMonadStore{
		monad:   []byte("test-monad"),
		version: 1,
	}

	server, _ := NewServer(sockPath, store)
	go server.Start()
	defer server.Stop()

	// Wait for socket to be ready
	waitForSocket(t, sockPath, 20)

	client, err := NewClient(sockPath)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// Close the client
	err = client.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify that further calls fail after close
	_, _, err = client.GetMonad()
	if err == nil {
		t.Error("Expected error after Close(), got nil")
	}
}

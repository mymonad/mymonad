package ipc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

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
	time.Sleep(100 * time.Millisecond)

	// Verify socket exists
	if _, err := os.Stat(sockPath); os.IsNotExist(err) {
		t.Fatal("Socket file should exist")
	}

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
	time.Sleep(100 * time.Millisecond)

	// Connect as client
	conn, err := grpc.Dial(
		"unix://"+sockPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewMonadStoreClient(conn)
	resp, err := client.GetMonad(context.Background(), &pb.GetMonadRequest{})
	if err != nil {
		t.Fatalf("GetMonad failed: %v", err)
	}

	if string(resp.EncryptedMonad) != string(expectedMonad) {
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
	time.Sleep(100 * time.Millisecond)

	// Connect as client
	conn, err := grpc.Dial(
		"unix://"+sockPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
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

# MyMonad v1.0 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a decentralized P2P matchmaking protocol where agents negotiate human compatibility through TEE-based privacy-preserving computation.

**Architecture:** Two separate Go daemons (Ingestion + P2P Agent) communicate via IPC. Ingestion daemon owns the Monad (affinity vector), built from local data via embedded transformer. P2P Agent participates in libp2p DHT and executes 5-stage handshake with TEE relay nodes.

**Tech Stack:** Go 1.22+, C++ (CGO for embedding engine), go-libp2p, protobuf/gRPC, ONNX Runtime or llama.cpp, Intel SGX SDK

---

## Phase 0: Project Scaffolding

### Task 0.1: Initialize Go Module

**Files:**
- Create: `go.mod`
- Create: `go.sum`
- Create: `Makefile`
- Create: `cmd/mymonad-ingest/main.go`
- Create: `cmd/mymonad-agent/main.go`
- Create: `cmd/mymonad-cli/main.go`

**Step 1: Initialize Go module**

```bash
cd /home/adrian/Projects/mymonad/.worktrees/v1-implementation
go mod init github.com/mymonad/mymonad
```

**Step 2: Create directory structure**

```bash
mkdir -p cmd/mymonad-ingest cmd/mymonad-agent cmd/mymonad-cli
mkdir -p internal/ingest internal/agent internal/ipc internal/crypto internal/config
mkdir -p pkg/monad pkg/protocol
mkdir -p tests/integration
```

**Step 3: Create minimal main.go files**

`cmd/mymonad-ingest/main.go`:
```go
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("mymonad-ingest starting...")
	os.Exit(0)
}
```

`cmd/mymonad-agent/main.go`:
```go
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("mymonad-agent starting...")
	os.Exit(0)
}
```

`cmd/mymonad-cli/main.go`:
```go
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("mymonad-cli")
	os.Exit(0)
}
```

**Step 4: Create Makefile**

`Makefile`:
```makefile
.PHONY: all build ingest agent cli test clean

GO := go
BINDIR := bin

all: build

build: ingest agent cli

ingest:
	$(GO) build -o $(BINDIR)/mymonad-ingest ./cmd/mymonad-ingest

agent:
	$(GO) build -o $(BINDIR)/mymonad-agent ./cmd/mymonad-agent

cli:
	$(GO) build -o $(BINDIR)/mymonad-cli ./cmd/mymonad-cli

test:
	$(GO) test -v -race -cover ./...

test-coverage:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

clean:
	rm -rf $(BINDIR)
	rm -f coverage.out coverage.html
```

**Step 5: Build and verify**

```bash
make all
./bin/mymonad-ingest
./bin/mymonad-agent
./bin/mymonad-cli
```

Expected: Each prints its startup message.

**Step 6: Commit**

```bash
git add -A
git commit -m "[Feat][Scaffold] Initialize Go module with multi-binary structure"
```

---

### Task 0.2: Add Core Dependencies

**Files:**
- Modify: `go.mod`

**Step 1: Add libp2p and protobuf dependencies**

```bash
go get github.com/libp2p/go-libp2p@latest
go get github.com/libp2p/go-libp2p-kad-dht@latest
go get google.golang.org/grpc@latest
go get google.golang.org/protobuf@latest
go get github.com/fsnotify/fsnotify@latest
go get golang.org/x/crypto@latest
go mod tidy
```

**Step 2: Verify build still works**

```bash
make clean && make all
```

**Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "[Update][Deps] Add libp2p, gRPC, fsnotify, and crypto dependencies"
```

---

## Phase 1: Cryptographic Identity

### Task 1.1: Ed25519 Keypair Generation

**Files:**
- Create: `internal/crypto/identity.go`
- Create: `internal/crypto/identity_test.go`

**Step 1: Write the failing test**

`internal/crypto/identity_test.go`:
```go
package crypto

import (
	"testing"
)

func TestGenerateIdentity(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	if identity.SigningKey == nil {
		t.Error("SigningKey should not be nil")
	}
	if identity.VerifyKey == nil {
		t.Error("VerifyKey should not be nil")
	}
	if len(identity.DID) == 0 {
		t.Error("DID should not be empty")
	}
}

func TestIdentityDIDFormat(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	// DID format: did:monad:<base58-pubkey>
	if len(identity.DID) < 15 {
		t.Errorf("DID too short: %s", identity.DID)
	}
	if identity.DID[:10] != "did:monad:" {
		t.Errorf("DID should start with 'did:monad:', got: %s", identity.DID)
	}
}
```

**Step 2: Run test to verify it fails**

```bash
go test -v ./internal/crypto/...
```

Expected: FAIL - package/types not defined.

**Step 3: Write minimal implementation**

`internal/crypto/identity.go`:
```go
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/mr-tron/base58"
)

// Identity holds the Ed25519 keypair and derived DID.
type Identity struct {
	SigningKey ed25519.PrivateKey
	VerifyKey  ed25519.PublicKey
	DID        string
}

// GenerateIdentity creates a new Ed25519 keypair and derives the DID.
func GenerateIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 keypair: %w", err)
	}

	did := "did:monad:" + base58.Encode(pub)

	return &Identity{
		SigningKey: priv,
		VerifyKey:  pub,
		DID:        did,
	}, nil
}
```

**Step 4: Add base58 dependency**

```bash
go get github.com/mr-tron/base58@latest
go mod tidy
```

**Step 5: Run test to verify it passes**

```bash
go test -v ./internal/crypto/...
```

Expected: PASS

**Step 6: Commit**

```bash
git add internal/crypto/ go.mod go.sum
git commit -m "[Feat][Crypto] Add Ed25519 identity generation with DID"
```

---

### Task 1.2: X25519 Key Derivation

**Files:**
- Modify: `internal/crypto/identity.go`
- Modify: `internal/crypto/identity_test.go`

**Step 1: Write the failing test**

Add to `internal/crypto/identity_test.go`:
```go
func TestIdentityEncryptionKey(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	if identity.EncryptionPrivate == nil {
		t.Error("EncryptionPrivate should not be nil")
	}
	if identity.EncryptionPublic == nil {
		t.Error("EncryptionPublic should not be nil")
	}
	if len(identity.EncryptionPrivate) != 32 {
		t.Errorf("EncryptionPrivate should be 32 bytes, got %d", len(identity.EncryptionPrivate))
	}
	if len(identity.EncryptionPublic) != 32 {
		t.Errorf("EncryptionPublic should be 32 bytes, got %d", len(identity.EncryptionPublic))
	}
}

func TestX25519KeyExchange(t *testing.T) {
	alice, _ := GenerateIdentity()
	bob, _ := GenerateIdentity()

	// Both should derive the same shared secret
	sharedAlice, err := alice.SharedSecret(bob.EncryptionPublic)
	if err != nil {
		t.Fatalf("Alice SharedSecret failed: %v", err)
	}

	sharedBob, err := bob.SharedSecret(alice.EncryptionPublic)
	if err != nil {
		t.Fatalf("Bob SharedSecret failed: %v", err)
	}

	if string(sharedAlice) != string(sharedBob) {
		t.Error("Shared secrets should match")
	}
}
```

**Step 2: Run test to verify it fails**

```bash
go test -v ./internal/crypto/...
```

Expected: FAIL - EncryptionPrivate/EncryptionPublic not defined.

**Step 3: Write implementation**

Update `internal/crypto/identity.go`:
```go
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"fmt"

	"github.com/mr-tron/base58"
	"golang.org/x/crypto/curve25519"
)

// Identity holds the Ed25519 keypair, derived X25519 keys, and DID.
type Identity struct {
	// Signing (Ed25519)
	SigningKey ed25519.PrivateKey
	VerifyKey  ed25519.PublicKey

	// Encryption (X25519, derived from Ed25519)
	EncryptionPrivate []byte
	EncryptionPublic  []byte

	DID string
}

// GenerateIdentity creates a new Ed25519 keypair and derives X25519 keys.
func GenerateIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 keypair: %w", err)
	}

	// Derive X25519 keys from Ed25519 seed
	// Ed25519 private key is 64 bytes: 32-byte seed + 32-byte public key
	seed := priv.Seed()
	h := sha512.Sum512(seed)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64

	var encPrivate [32]byte
	copy(encPrivate[:], h[:32])

	var encPublic [32]byte
	curve25519.ScalarBaseMult(&encPublic, &encPrivate)

	did := "did:monad:" + base58.Encode(pub)

	return &Identity{
		SigningKey:        priv,
		VerifyKey:         pub,
		EncryptionPrivate: encPrivate[:],
		EncryptionPublic:  encPublic[:],
		DID:               did,
	}, nil
}

// SharedSecret computes X25519 shared secret with peer's public key.
func (i *Identity) SharedSecret(peerPublic []byte) ([]byte, error) {
	if len(peerPublic) != 32 {
		return nil, fmt.Errorf("peer public key must be 32 bytes")
	}

	var privKey, pubKey, shared [32]byte
	copy(privKey[:], i.EncryptionPrivate)
	copy(pubKey[:], peerPublic)

	curve25519.ScalarMult(&shared, &privKey, &pubKey)

	return shared[:], nil
}
```

**Step 4: Run test to verify it passes**

```bash
go test -v ./internal/crypto/...
```

Expected: PASS

**Step 5: Commit**

```bash
git add internal/crypto/
git commit -m "[Feat][Crypto] Add X25519 key derivation and shared secret"
```

---

### Task 1.3: Identity Persistence (Encrypted)

**Files:**
- Create: `internal/crypto/storage.go`
- Create: `internal/crypto/storage_test.go`

**Step 1: Write the failing test**

`internal/crypto/storage_test.go`:
```go
package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoadIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "keypair.enc")
	passphrase := "test-passphrase-123"

	// Generate identity
	original, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	// Save encrypted
	err = SaveIdentity(original, keyPath, passphrase)
	if err != nil {
		t.Fatalf("SaveIdentity failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("Key file should exist")
	}

	// Load and decrypt
	loaded, err := LoadIdentity(keyPath, passphrase)
	if err != nil {
		t.Fatalf("LoadIdentity failed: %v", err)
	}

	// Verify loaded matches original
	if loaded.DID != original.DID {
		t.Errorf("DID mismatch: got %s, want %s", loaded.DID, original.DID)
	}
	if string(loaded.EncryptionPublic) != string(original.EncryptionPublic) {
		t.Error("EncryptionPublic mismatch")
	}
}

func TestLoadIdentityWrongPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "keypair.enc")

	identity, _ := GenerateIdentity()
	SaveIdentity(identity, keyPath, "correct-passphrase")

	_, err := LoadIdentity(keyPath, "wrong-passphrase")
	if err == nil {
		t.Error("LoadIdentity should fail with wrong passphrase")
	}
}
```

**Step 2: Run test to verify it fails**

```bash
go test -v ./internal/crypto/...
```

Expected: FAIL - SaveIdentity/LoadIdentity not defined.

**Step 3: Write implementation**

`internal/crypto/storage.go`:
```go
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
)

// serializedIdentity is the JSON structure for storage.
type serializedIdentity struct {
	SigningKey        []byte `json:"signing_key"`
	VerifyKey         []byte `json:"verify_key"`
	EncryptionPrivate []byte `json:"encryption_private"`
	EncryptionPublic  []byte `json:"encryption_public"`
	DID               string `json:"did"`
}

// deriveKey uses Argon2id to derive an AES-256 key from passphrase.
func deriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
}

// SaveIdentity encrypts and saves identity to file.
func SaveIdentity(id *Identity, path, passphrase string) error {
	// Serialize identity
	data, err := json.Marshal(serializedIdentity{
		SigningKey:        id.SigningKey,
		VerifyKey:         id.VerifyKey,
		EncryptionPrivate: id.EncryptionPrivate,
		EncryptionPublic:  id.EncryptionPublic,
		DID:               id.DID,
	})
	if err != nil {
		return fmt.Errorf("failed to serialize identity: %w", err)
	}

	// Generate salt
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key
	key := deriveKey(passphrase, salt)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Write: salt + nonce + ciphertext
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(salt); err != nil {
		return err
	}
	if _, err := f.Write(nonce); err != nil {
		return err
	}
	if _, err := f.Write(ciphertext); err != nil {
		return err
	}

	return nil
}

// LoadIdentity decrypts and loads identity from file.
func LoadIdentity(path, passphrase string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	if len(data) < 28 { // 16 salt + 12 nonce minimum
		return nil, fmt.Errorf("file too short")
	}

	salt := data[:16]
	key := deriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	nonce := data[16 : 16+nonceSize]
	ciphertext := data[16+nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong passphrase?): %w", err)
	}

	var stored serializedIdentity
	if err := json.Unmarshal(plaintext, &stored); err != nil {
		return nil, fmt.Errorf("failed to deserialize identity: %w", err)
	}

	return &Identity{
		SigningKey:        stored.SigningKey,
		VerifyKey:         stored.VerifyKey,
		EncryptionPrivate: stored.EncryptionPrivate,
		EncryptionPublic:  stored.EncryptionPublic,
		DID:               stored.DID,
	}, nil
}
```

**Step 4: Run test to verify it passes**

```bash
go test -v ./internal/crypto/...
```

Expected: PASS

**Step 5: Commit**

```bash
git add internal/crypto/
git commit -m "[Feat][Crypto] Add encrypted identity storage with Argon2id + AES-GCM"
```

---

## Phase 2: IPC Layer

### Task 2.1: Define Protobuf Schema

**Files:**
- Create: `api/proto/monad.proto`
- Create: `api/proto/generate.go`

**Step 1: Create proto directory**

```bash
mkdir -p api/proto
```

**Step 2: Write protobuf schema**

`api/proto/monad.proto`:
```protobuf
syntax = "proto3";

package monad;

option go_package = "github.com/mymonad/mymonad/api/proto";

// MonadStore is the IPC service exposed by the Ingestion Daemon.
service MonadStore {
  // GetMonad returns the current encrypted Monad.
  rpc GetMonad(GetMonadRequest) returns (GetMonadResponse);

  // WatchMonad streams updates when the Monad changes.
  rpc WatchMonad(WatchMonadRequest) returns (stream MonadUpdate);

  // Status returns the ingestion daemon status.
  rpc Status(StatusRequest) returns (StatusResponse);
}

message GetMonadRequest {}

message GetMonadResponse {
  bytes encrypted_monad = 1;
  int64 version = 2;
  int64 last_updated = 3; // Unix timestamp
}

message WatchMonadRequest {}

message MonadUpdate {
  bytes encrypted_monad = 1;
  int64 version = 2;
  int64 timestamp = 3;
}

message StatusRequest {}

message StatusResponse {
  bool ready = 1;
  int64 documents_indexed = 2;
  int64 last_scan_timestamp = 3;
  string state = 4; // "idle", "scanning", "embedding"
}
```

**Step 3: Create generate.go for go:generate**

`api/proto/generate.go`:
```go
//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative monad.proto

package proto
```

**Step 4: Install protoc plugins and generate**

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
cd api/proto && go generate
```

Note: User must have `protoc` installed. If not:
```bash
# Ubuntu/Debian
sudo apt install protobuf-compiler
```

**Step 5: Verify generated files exist**

```bash
ls api/proto/*.pb.go
```

Expected: `monad.pb.go` and `monad_grpc.pb.go`

**Step 6: Commit**

```bash
git add api/proto/
git commit -m "[Feat][IPC] Add protobuf schema for MonadStore service"
```

---

### Task 2.2: IPC Server (Unix Socket)

**Files:**
- Create: `internal/ipc/server.go`
- Create: `internal/ipc/server_test.go`

**Step 1: Write the failing test**

`internal/ipc/server_test.go`:
```go
package ipc

import (
	"context"
	"net"
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
```

**Step 2: Run test to verify it fails**

```bash
go test -v ./internal/ipc/...
```

Expected: FAIL - NewServer not defined.

**Step 3: Write implementation**

`internal/ipc/server.go`:
```go
package ipc

import (
	"context"
	"net"
	"os"
	"sync"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
	"google.golang.org/grpc"
)

// MonadProvider is the interface for accessing the Monad.
type MonadProvider interface {
	GetMonad() (data []byte, version int64, err error)
	GetStatus() (ready bool, docsIndexed int64, state string)
}

// Server is the IPC gRPC server.
type Server struct {
	pb.UnimplementedMonadStoreServer

	sockPath string
	provider MonadProvider
	grpc     *grpc.Server
	listener net.Listener
	mu       sync.RWMutex
}

// NewServer creates a new IPC server.
func NewServer(sockPath string, provider MonadProvider) (*Server, error) {
	// Remove existing socket if present
	os.Remove(sockPath)

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}

	s := &Server{
		sockPath: sockPath,
		provider: provider,
		grpc:     grpc.NewServer(),
		listener: listener,
	}

	pb.RegisterMonadStoreServer(s.grpc, s)

	return s, nil
}

// Start begins serving requests.
func (s *Server) Start() error {
	return s.grpc.Serve(s.listener)
}

// Stop gracefully stops the server.
func (s *Server) Stop() {
	s.grpc.GracefulStop()
	os.Remove(s.sockPath)
}

// GetMonad implements the gRPC method.
func (s *Server) GetMonad(ctx context.Context, req *pb.GetMonadRequest) (*pb.GetMonadResponse, error) {
	data, version, err := s.provider.GetMonad()
	if err != nil {
		return nil, err
	}

	return &pb.GetMonadResponse{
		EncryptedMonad: data,
		Version:        version,
		LastUpdated:    time.Now().Unix(),
	}, nil
}

// Status implements the gRPC method.
func (s *Server) Status(ctx context.Context, req *pb.StatusRequest) (*pb.StatusResponse, error) {
	ready, docs, state := s.provider.GetStatus()

	return &pb.StatusResponse{
		Ready:             ready,
		DocumentsIndexed:  docs,
		LastScanTimestamp: time.Now().Unix(),
		State:             state,
	}, nil
}
```

**Step 4: Run test to verify it passes**

```bash
go test -v ./internal/ipc/...
```

Expected: PASS

**Step 5: Commit**

```bash
git add internal/ipc/
git commit -m "[Feat][IPC] Add gRPC server over Unix socket"
```

---

### Task 2.3: IPC Client

**Files:**
- Create: `internal/ipc/client.go`
- Modify: `internal/ipc/server_test.go` (add client tests)

**Step 1: Write the failing test**

Add to `internal/ipc/server_test.go`:
```go
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
	time.Sleep(100 * time.Millisecond)

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

	if string(monad) != string(expectedMonad) {
		t.Errorf("Monad mismatch")
	}
	if version != 99 {
		t.Errorf("Version mismatch: got %d, want 99", version)
	}
}
```

**Step 2: Run test to verify it fails**

```bash
go test -v ./internal/ipc/...
```

Expected: FAIL - NewClient not defined.

**Step 3: Write implementation**

`internal/ipc/client.go`:
```go
package ipc

import (
	"context"
	"fmt"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client is the IPC client for connecting to the Ingestion Daemon.
type Client struct {
	conn   *grpc.ClientConn
	client pb.MonadStoreClient
}

// NewClient creates a new IPC client.
func NewClient(sockPath string) (*Client, error) {
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

// Close closes the connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// GetMonad retrieves the current Monad from the Ingestion Daemon.
func (c *Client) GetMonad() ([]byte, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.client.GetMonad(ctx, &pb.GetMonadRequest{})
	if err != nil {
		return nil, 0, fmt.Errorf("GetMonad RPC failed: %w", err)
	}

	return resp.EncryptedMonad, resp.Version, nil
}

// Status retrieves the Ingestion Daemon status.
func (c *Client) Status() (ready bool, docsIndexed int64, state string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.client.Status(ctx, &pb.StatusRequest{})
	if err != nil {
		return false, 0, "", fmt.Errorf("Status RPC failed: %w", err)
	}

	return resp.Ready, resp.DocumentsIndexed, resp.State, nil
}
```

**Step 4: Run test to verify it passes**

```bash
go test -v ./internal/ipc/...
```

Expected: PASS

**Step 5: Commit**

```bash
git add internal/ipc/
git commit -m "[Feat][IPC] Add gRPC client for agent-to-ingestion communication"
```

---

## Phase 3: Monad Storage

### Task 3.1: Monad Type Definition

**Files:**
- Create: `pkg/monad/monad.go`
- Create: `pkg/monad/monad_test.go`

**Step 1: Write the failing test**

`pkg/monad/monad_test.go`:
```go
package monad

import (
	"testing"
)

func TestNewMonad(t *testing.T) {
	dims := 384 // Standard embedding dimension
	m := New(dims)

	if m == nil {
		t.Fatal("New returned nil")
	}
	if len(m.Vector) != dims {
		t.Errorf("Vector length: got %d, want %d", len(m.Vector), dims)
	}
	if m.Version != 0 {
		t.Errorf("Initial version should be 0, got %d", m.Version)
	}
}

func TestMonadUpdate(t *testing.T) {
	m := New(3)

	// Initial vector is zeros
	for i, v := range m.Vector {
		if v != 0 {
			t.Errorf("Initial vector[%d] should be 0, got %f", i, v)
		}
	}

	// Update with a document embedding
	docEmbedding := []float32{0.5, 0.3, 0.2}
	m.Update(docEmbedding)

	if m.Version != 1 {
		t.Errorf("Version after update should be 1, got %d", m.Version)
	}

	// Vector should be updated (running average)
	if m.Vector[0] != 0.5 {
		t.Errorf("Vector[0] after first update should be 0.5, got %f", m.Vector[0])
	}
}

func TestMonadCosineSimilarity(t *testing.T) {
	a := New(3)
	a.Vector = []float32{1, 0, 0}

	b := New(3)
	b.Vector = []float32{1, 0, 0}

	sim := a.CosineSimilarity(b)
	if sim < 0.999 {
		t.Errorf("Identical vectors should have similarity ~1.0, got %f", sim)
	}

	// Orthogonal
	c := New(3)
	c.Vector = []float32{0, 1, 0}

	sim = a.CosineSimilarity(c)
	if sim > 0.001 {
		t.Errorf("Orthogonal vectors should have similarity ~0, got %f", sim)
	}
}
```

**Step 2: Run test to verify it fails**

```bash
go test -v ./pkg/monad/...
```

Expected: FAIL - New not defined.

**Step 3: Write implementation**

`pkg/monad/monad.go`:
```go
package monad

import (
	"math"
	"sync"
	"time"
)

// Monad represents the user's affinity vector.
type Monad struct {
	Vector      []float32
	Version     int64
	UpdatedAt   time.Time
	DocCount    int64 // Number of documents contributing to this vector
	mu          sync.RWMutex
}

// New creates a new Monad with the specified dimensions.
func New(dimensions int) *Monad {
	return &Monad{
		Vector:    make([]float32, dimensions),
		Version:   0,
		UpdatedAt: time.Now(),
		DocCount:  0,
	}
}

// Update incorporates a new document embedding using running average.
func (m *Monad) Update(docEmbedding []float32) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(docEmbedding) != len(m.Vector) {
		return // Dimension mismatch, ignore
	}

	m.DocCount++
	weight := 1.0 / float32(m.DocCount)

	for i := range m.Vector {
		// Running average: new = old * (n-1)/n + new * 1/n
		m.Vector[i] = m.Vector[i]*(1-weight) + docEmbedding[i]*weight
	}

	m.Version++
	m.UpdatedAt = time.Now()
}

// CosineSimilarity computes similarity with another Monad.
func (m *Monad) CosineSimilarity(other *Monad) float32 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.Vector) != len(other.Vector) {
		return 0
	}

	var dot, normA, normB float64
	for i := range m.Vector {
		a := float64(m.Vector[i])
		b := float64(other.Vector[i])
		dot += a * b
		normA += a * a
		normB += b * b
	}

	if normA == 0 || normB == 0 {
		return 0
	}

	return float32(dot / (math.Sqrt(normA) * math.Sqrt(normB)))
}

// Clone returns a deep copy of the Monad.
func (m *Monad) Clone() *Monad {
	m.mu.RLock()
	defer m.mu.RUnlock()

	clone := &Monad{
		Vector:    make([]float32, len(m.Vector)),
		Version:   m.Version,
		UpdatedAt: m.UpdatedAt,
		DocCount:  m.DocCount,
	}
	copy(clone.Vector, m.Vector)
	return clone
}
```

**Step 4: Run test to verify it passes**

```bash
go test -v ./pkg/monad/...
```

Expected: PASS

**Step 5: Commit**

```bash
git add pkg/monad/
git commit -m "[Feat][Monad] Add Monad type with update and cosine similarity"
```

---

### Task 3.2: Monad Serialization & Encryption

**Files:**
- Create: `pkg/monad/storage.go`
- Create: `pkg/monad/storage_test.go`

**Step 1: Write the failing test**

`pkg/monad/storage_test.go`:
```go
package monad

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMonadSaveLoad(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "monad.enc")
	key := make([]byte, 32) // Zero key for testing

	original := New(3)
	original.Vector = []float32{0.1, 0.2, 0.3}
	original.Version = 5
	original.DocCount = 100

	err := Save(original, path, key)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("File should exist")
	}

	loaded, err := Load(path, key)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Version != original.Version {
		t.Errorf("Version mismatch: got %d, want %d", loaded.Version, original.Version)
	}
	if loaded.DocCount != original.DocCount {
		t.Errorf("DocCount mismatch: got %d, want %d", loaded.DocCount, original.DocCount)
	}
	for i := range original.Vector {
		if loaded.Vector[i] != original.Vector[i] {
			t.Errorf("Vector[%d] mismatch: got %f, want %f", i, loaded.Vector[i], original.Vector[i])
		}
	}
}

func TestMonadLoadWrongKey(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "monad.enc")
	correctKey := []byte("correct-key-32-bytes-long-xxxxx")
	wrongKey := []byte("wrong-key-32-bytes-long-xxxxxxx")

	m := New(3)
	m.Vector = []float32{0.1, 0.2, 0.3}
	Save(m, path, correctKey)

	_, err := Load(path, wrongKey)
	if err == nil {
		t.Error("Load should fail with wrong key")
	}
}
```

**Step 2: Run test to verify it fails**

```bash
go test -v ./pkg/monad/...
```

Expected: FAIL - Save/Load not defined.

**Step 3: Write implementation**

`pkg/monad/storage.go`:
```go
package monad

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"time"
)

// Save encrypts and saves the Monad to disk.
// Key must be 32 bytes (AES-256).
func Save(m *Monad, path string, key []byte) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Serialize: version(8) + doccount(8) + updated(8) + dims(4) + vector(dims*4)
	dims := len(m.Vector)
	dataLen := 8 + 8 + 8 + 4 + dims*4
	data := make([]byte, dataLen)

	binary.LittleEndian.PutUint64(data[0:8], uint64(m.Version))
	binary.LittleEndian.PutUint64(data[8:16], uint64(m.DocCount))
	binary.LittleEndian.PutUint64(data[16:24], uint64(m.UpdatedAt.Unix()))
	binary.LittleEndian.PutUint32(data[24:28], uint32(dims))

	offset := 28
	for _, v := range m.Vector {
		binary.LittleEndian.PutUint32(data[offset:offset+4], math.Float32bits(v))
		offset += 4
	}

	// Encrypt with AES-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Write: nonce + ciphertext
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(nonce); err != nil {
		return err
	}
	if _, err := f.Write(ciphertext); err != nil {
		return err
	}

	return nil
}

// Load decrypts and loads a Monad from disk.
func Load(path string, key []byte) (*Monad, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("file too short")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	if len(plaintext) < 28 {
		return nil, fmt.Errorf("data too short")
	}

	version := int64(binary.LittleEndian.Uint64(plaintext[0:8]))
	docCount := int64(binary.LittleEndian.Uint64(plaintext[8:16]))
	updatedUnix := int64(binary.LittleEndian.Uint64(plaintext[16:24]))
	dims := int(binary.LittleEndian.Uint32(plaintext[24:28]))

	expectedLen := 28 + dims*4
	if len(plaintext) < expectedLen {
		return nil, fmt.Errorf("data length mismatch")
	}

	vector := make([]float32, dims)
	offset := 28
	for i := range vector {
		bits := binary.LittleEndian.Uint32(plaintext[offset : offset+4])
		vector[i] = math.Float32frombits(bits)
		offset += 4
	}

	return &Monad{
		Vector:    vector,
		Version:   version,
		DocCount:  docCount,
		UpdatedAt: time.Unix(updatedUnix, 0),
	}, nil
}
```

**Step 4: Run test to verify it passes**

```bash
go test -v ./pkg/monad/...
```

Expected: PASS

**Step 5: Commit**

```bash
git add pkg/monad/
git commit -m "[Feat][Monad] Add encrypted storage for Monad persistence"
```

---

## Phase 4: File Watcher (Ingestion Foundation)

### Task 4.1: inotify Watcher

**Files:**
- Create: `internal/ingest/watcher.go`
- Create: `internal/ingest/watcher_test.go`

**Step 1: Write the failing test**

`internal/ingest/watcher_test.go`:
```go
package ingest

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatcherDetectsNewFile(t *testing.T) {
	tmpDir := t.TempDir()

	events := make(chan FileEvent, 10)
	watcher, err := NewWatcher(tmpDir, events)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer watcher.Close()

	go watcher.Start()

	// Create a new file
	testFile := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(testFile, []byte("hello"), 0644)

	// Wait for event
	select {
	case event := <-events:
		if event.Path != testFile {
			t.Errorf("Path mismatch: got %s, want %s", event.Path, testFile)
		}
		if event.Op != OpCreate {
			t.Errorf("Op should be OpCreate, got %v", event.Op)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for event")
	}
}

func TestWatcherDetectsModify(t *testing.T) {
	tmpDir := t.TempDir()

	// Create file before watching
	testFile := filepath.Join(tmpDir, "existing.txt")
	os.WriteFile(testFile, []byte("initial"), 0644)

	events := make(chan FileEvent, 10)
	watcher, err := NewWatcher(tmpDir, events)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer watcher.Close()

	go watcher.Start()
	time.Sleep(100 * time.Millisecond)

	// Modify the file
	os.WriteFile(testFile, []byte("modified"), 0644)

	// Wait for event
	select {
	case event := <-events:
		if event.Op != OpModify && event.Op != OpCreate {
			t.Errorf("Op should be OpModify or OpCreate, got %v", event.Op)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for event")
	}
}
```

**Step 2: Run test to verify it fails**

```bash
go test -v ./internal/ingest/...
```

Expected: FAIL - NewWatcher not defined.

**Step 3: Write implementation**

`internal/ingest/watcher.go`:
```go
package ingest

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
)

// Op represents the type of file operation.
type Op int

const (
	OpCreate Op = iota
	OpModify
	OpDelete
)

// FileEvent represents a file system event.
type FileEvent struct {
	Path string
	Op   Op
}

// Watcher monitors a directory for file changes.
type Watcher struct {
	root     string
	events   chan<- FileEvent
	fsw      *fsnotify.Watcher
	excludes []string
}

// DefaultExcludes are patterns to ignore.
var DefaultExcludes = []string{
	".git",
	"node_modules",
	".cache",
	"__pycache__",
	".tmp",
}

// NewWatcher creates a new file watcher for the given directory.
func NewWatcher(root string, events chan<- FileEvent) (*Watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	w := &Watcher{
		root:     root,
		events:   events,
		fsw:      fsw,
		excludes: DefaultExcludes,
	}

	// Add root and subdirectories
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip inaccessible paths
		}
		if info.IsDir() {
			if w.shouldExclude(path) {
				return filepath.SkipDir
			}
			return fsw.Add(path)
		}
		return nil
	})
	if err != nil {
		fsw.Close()
		return nil, err
	}

	return w, nil
}

// shouldExclude checks if a path should be excluded.
func (w *Watcher) shouldExclude(path string) bool {
	base := filepath.Base(path)
	for _, exc := range w.excludes {
		if strings.Contains(base, exc) {
			return true
		}
	}
	return false
}

// Start begins watching for events (blocking).
func (w *Watcher) Start() {
	for {
		select {
		case event, ok := <-w.fsw.Events:
			if !ok {
				return
			}

			if w.shouldExclude(event.Name) {
				continue
			}

			var op Op
			switch {
			case event.Op&fsnotify.Create != 0:
				op = OpCreate
				// If it's a new directory, add it to watch
				if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
					w.fsw.Add(event.Name)
				}
			case event.Op&fsnotify.Write != 0:
				op = OpModify
			case event.Op&fsnotify.Remove != 0:
				op = OpDelete
			default:
				continue
			}

			w.events <- FileEvent{
				Path: event.Name,
				Op:   op,
			}

		case _, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			// Log error in production; skip for now
		}
	}
}

// Close stops the watcher.
func (w *Watcher) Close() error {
	return w.fsw.Close()
}
```

**Step 4: Run test to verify it passes**

```bash
go test -v ./internal/ingest/...
```

Expected: PASS

**Step 5: Commit**

```bash
git add internal/ingest/
git commit -m "[Feat][Ingest] Add inotify-based file watcher"
```

---

## Phase 5: P2P Network Foundation

### Task 5.1: libp2p Host Setup

**Files:**
- Create: `internal/agent/host.go`
- Create: `internal/agent/host_test.go`

**Step 1: Write the failing test**

`internal/agent/host_test.go`:
```go
package agent

import (
	"context"
	"testing"
	"time"
)

func TestNewHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	host, err := NewHost(ctx, 0) // 0 = random port
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Close()

	if host.ID() == "" {
		t.Error("Host ID should not be empty")
	}

	addrs := host.Addrs()
	if len(addrs) == 0 {
		t.Error("Host should have at least one address")
	}
}

func TestTwoHostsConnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	host1, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost 1 failed: %v", err)
	}
	defer host1.Close()

	host2, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost 2 failed: %v", err)
	}
	defer host2.Close()

	// Connect host2 to host1
	err = host2.Connect(ctx, host1.AddrInfo())
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// Verify connection
	peers := host2.Peers()
	found := false
	for _, p := range peers {
		if p == host1.ID() {
			found = true
			break
		}
	}
	if !found {
		t.Error("host2 should be connected to host1")
	}
}
```

**Step 2: Run test to verify it fails**

```bash
go test -v ./internal/agent/...
```

Expected: FAIL - NewHost not defined.

**Step 3: Write implementation**

`internal/agent/host.go`:
```go
package agent

import (
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// Host wraps a libp2p host.
type Host struct {
	h host.Host
}

// NewHost creates a new libp2p host.
func NewHost(ctx context.Context, port int) (*Host, error) {
	addr := fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port)

	h, err := libp2p.New(
		libp2p.ListenAddrStrings(addr),
		libp2p.DisableRelay(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	return &Host{h: h}, nil
}

// ID returns the peer ID.
func (h *Host) ID() peer.ID {
	return h.h.ID()
}

// Addrs returns the listen addresses.
func (h *Host) Addrs() []multiaddr.Multiaddr {
	return h.h.Addrs()
}

// AddrInfo returns the peer.AddrInfo for this host.
func (h *Host) AddrInfo() peer.AddrInfo {
	return peer.AddrInfo{
		ID:    h.h.ID(),
		Addrs: h.h.Addrs(),
	}
}

// Connect connects to another peer.
func (h *Host) Connect(ctx context.Context, pi peer.AddrInfo) error {
	return h.h.Connect(ctx, pi)
}

// Peers returns connected peer IDs.
func (h *Host) Peers() []peer.ID {
	return h.h.Network().Peers()
}

// Close shuts down the host.
func (h *Host) Close() error {
	return h.h.Close()
}

// Host returns the underlying libp2p host.
func (h *Host) Host() host.Host {
	return h.h
}
```

**Step 4: Run test to verify it passes**

```bash
go test -v ./internal/agent/...
```

Expected: PASS

**Step 5: Commit**

```bash
git add internal/agent/
git commit -m "[Feat][Agent] Add libp2p host wrapper"
```

---

### Task 5.2: Kademlia DHT Setup

**Files:**
- Create: `internal/agent/dht.go`
- Create: `internal/agent/dht_test.go`

**Step 1: Write the failing test**

`internal/agent/dht_test.go`:
```go
package agent

import (
	"context"
	"testing"
	"time"
)

func TestDHTBootstrap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create two nodes
	host1, _ := NewHost(ctx, 0)
	defer host1.Close()

	host2, _ := NewHost(ctx, 0)
	defer host2.Close()

	// Create DHTs
	dht1, err := NewDHT(ctx, host1)
	if err != nil {
		t.Fatalf("NewDHT 1 failed: %v", err)
	}
	defer dht1.Close()

	dht2, err := NewDHT(ctx, host2)
	if err != nil {
		t.Fatalf("NewDHT 2 failed: %v", err)
	}
	defer dht2.Close()

	// Connect and bootstrap
	host2.Connect(ctx, host1.AddrInfo())

	err = dht1.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("Bootstrap 1 failed: %v", err)
	}

	err = dht2.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("Bootstrap 2 failed: %v", err)
	}

	// Give time for routing table to populate
	time.Sleep(500 * time.Millisecond)

	// Both should find each other
	if len(dht1.RoutingTable().ListPeers()) == 0 {
		t.Error("DHT1 routing table should not be empty")
	}
}

func TestDHTPutGet(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	host1, _ := NewHost(ctx, 0)
	defer host1.Close()

	host2, _ := NewHost(ctx, 0)
	defer host2.Close()

	dht1, _ := NewDHT(ctx, host1)
	defer dht1.Close()

	dht2, _ := NewDHT(ctx, host2)
	defer dht2.Close()

	host2.Connect(ctx, host1.AddrInfo())
	dht1.Bootstrap(ctx)
	dht2.Bootstrap(ctx)
	time.Sleep(500 * time.Millisecond)

	// Put a value
	key := "/mymonad/test/key1"
	value := []byte("test-value")

	err := dht1.PutValue(ctx, key, value)
	if err != nil {
		t.Fatalf("PutValue failed: %v", err)
	}

	// Get from other node
	retrieved, err := dht2.GetValue(ctx, key)
	if err != nil {
		t.Fatalf("GetValue failed: %v", err)
	}

	if string(retrieved) != string(value) {
		t.Errorf("Value mismatch: got %s, want %s", retrieved, value)
	}
}
```

**Step 2: Run test to verify it fails**

```bash
go test -v ./internal/agent/...
```

Expected: FAIL - NewDHT not defined.

**Step 3: Write implementation**

`internal/agent/dht.go`:
```go
package agent

import (
	"context"
	"fmt"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/routing"
	kb "github.com/libp2p/go-libp2p-kbucket"
)

// DHT wraps the Kademlia DHT.
type DHT struct {
	dht *dht.IpfsDHT
}

// NewDHT creates a new Kademlia DHT.
func NewDHT(ctx context.Context, host *Host) (*DHT, error) {
	d, err := dht.New(ctx, host.Host(),
		dht.Mode(dht.ModeAutoServer),
		dht.ProtocolPrefix("/mymonad"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create DHT: %w", err)
	}

	return &DHT{dht: d}, nil
}

// Bootstrap connects to bootstrap peers and refreshes routing table.
func (d *DHT) Bootstrap(ctx context.Context) error {
	return d.dht.Bootstrap(ctx)
}

// RoutingTable returns the DHT routing table.
func (d *DHT) RoutingTable() *kb.RoutingTable {
	return d.dht.RoutingTable()
}

// PutValue stores a value in the DHT.
func (d *DHT) PutValue(ctx context.Context, key string, value []byte) error {
	return d.dht.PutValue(ctx, key, value)
}

// GetValue retrieves a value from the DHT.
func (d *DHT) GetValue(ctx context.Context, key string) ([]byte, error) {
	return d.dht.GetValue(ctx, key)
}

// Provide announces that this node can provide a key.
func (d *DHT) Provide(ctx context.Context, key string) error {
	c, err := contentID(key)
	if err != nil {
		return err
	}
	return d.dht.Provide(ctx, c, true)
}

// FindProviders finds nodes that provide a key.
func (d *DHT) FindProviders(ctx context.Context, key string, count int) (<-chan routing.PeerInfo, error) {
	c, err := contentID(key)
	if err != nil {
		return nil, err
	}
	ch := d.dht.FindProvidersAsync(ctx, c, count)

	// Convert to routing.PeerInfo channel
	out := make(chan routing.PeerInfo)
	go func() {
		defer close(out)
		for pi := range ch {
			out <- routing.PeerInfo{ID: pi.ID, Addrs: pi.Addrs}
		}
	}()
	return out, nil
}

// Close shuts down the DHT.
func (d *DHT) Close() error {
	return d.dht.Close()
}

// contentID creates a CID from a string key.
func contentID(key string) (interface{ String() string }, error) {
	// Use the key directly for now; in production, hash it
	return &simpleKey{key}, nil
}

type simpleKey struct {
	s string
}

func (k *simpleKey) String() string { return k.s }
```

**Step 4: Fix import and run test**

The DHT needs proper CID handling. Let's simplify:

```bash
go get github.com/ipfs/go-cid@latest
go mod tidy
```

Update `internal/agent/dht.go` to use proper CID:
```go
package agent

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/ipfs/go-cid"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	kb "github.com/libp2p/go-libp2p-kbucket"
	mh "github.com/multiformats/go-multihash"
)

// DHT wraps the Kademlia DHT.
type DHT struct {
	dht *dht.IpfsDHT
}

// NewDHT creates a new Kademlia DHT.
func NewDHT(ctx context.Context, host *Host) (*DHT, error) {
	d, err := dht.New(ctx, host.Host(),
		dht.Mode(dht.ModeAutoServer),
		dht.ProtocolPrefix("/mymonad"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create DHT: %w", err)
	}

	return &DHT{dht: d}, nil
}

// Bootstrap connects to bootstrap peers and refreshes routing table.
func (d *DHT) Bootstrap(ctx context.Context) error {
	return d.dht.Bootstrap(ctx)
}

// RoutingTable returns the DHT routing table.
func (d *DHT) RoutingTable() *kb.RoutingTable {
	return d.dht.RoutingTable()
}

// PutValue stores a value in the DHT.
func (d *DHT) PutValue(ctx context.Context, key string, value []byte) error {
	return d.dht.PutValue(ctx, key, value)
}

// GetValue retrieves a value from the DHT.
func (d *DHT) GetValue(ctx context.Context, key string) ([]byte, error) {
	return d.dht.GetValue(ctx, key)
}

// Provide announces that this node can provide a key.
func (d *DHT) Provide(ctx context.Context, key string) error {
	c := makeCID(key)
	return d.dht.Provide(ctx, c, true)
}

// FindProviders finds nodes that provide a key.
func (d *DHT) FindProviders(ctx context.Context, key string, count int) <-chan AddrInfo {
	c := makeCID(key)
	return d.dht.FindProvidersAsync(ctx, c, count)
}

// Close shuts down the DHT.
func (d *DHT) Close() error {
	return d.dht.Close()
}

// makeCID creates a CID from a string key.
func makeCID(key string) cid.Cid {
	h := sha256.Sum256([]byte(key))
	mhash, _ := mh.Encode(h[:], mh.SHA2_256)
	return cid.NewCidV1(cid.Raw, mhash)
}

// AddrInfo is re-exported for convenience.
type AddrInfo = dht.AddrInfo
```

**Step 5: Run test to verify it passes**

```bash
go test -v ./internal/agent/...
```

Expected: PASS (or adjust based on actual libp2p API)

**Step 6: Commit**

```bash
git add internal/agent/ go.mod go.sum
git commit -m "[Feat][Agent] Add Kademlia DHT wrapper"
```

---

## Remaining Phases (Summary)

The following phases continue the same TDD pattern:

### Phase 6: Handshake Protocol
- Task 6.1: Define handshake state machine
- Task 6.2: Stage 1 - Attestation (PoW + signature verification)
- Task 6.3: Stage 2 - Vector match request/response
- Task 6.4: Stage 3 - Deal-breaker exchange
- Task 6.5: Stage 4 - Human chat relay
- Task 6.6: Stage 5 - Unmask exchange

### Phase 7: LSH for Interest Hashing
- Task 7.1: Implement random hyperplane LSH
- Task 7.2: LSH signature generation from Monad
- Task 7.3: DHT publication of LSH hashes

### Phase 8: Hashcash PoW
- Task 8.1: Hashcash puzzle generation
- Task 8.2: Hashcash verification

### Phase 9: Embedding Engine (C++/CGO)
- Task 9.1: CGO build setup
- Task 9.2: ONNX Runtime integration
- Task 9.3: Text-to-embedding pipeline

### Phase 10: Text Extractors
- Task 10.1: Plain text extractor
- Task 10.2: PDF extractor
- Task 10.3: Email (mbox/Maildir) extractor
- Task 10.4: Browser history extractor

### Phase 11: Daemon Integration
- Task 11.1: Ingestion daemon main loop
- Task 11.2: Agent daemon main loop
- Task 11.3: CLI commands (status, visibility, config)

### Phase 12: TEE Relay (Placeholder)
- Task 12.1: Mock TEE relay for development
- Task 12.2: TEE relay protocol definition
- (SGX implementation deferred to specialized hardware work)

---

## Testing Checklist

Before each commit:
- [ ] All unit tests pass: `go test ./...`
- [ ] Race detector clean: `go test -race ./...`
- [ ] Coverage >= 80%: `go test -cover ./...`

Before PR:
- [ ] Integration tests pass: `make test-integration`
- [ ] Linter clean: `golangci-lint run`
- [ ] Build succeeds: `make all`

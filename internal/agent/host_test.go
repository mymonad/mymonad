package agent

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
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

func TestHostWithSpecificPort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Use a specific port
	port := 19876
	host, err := NewHost(ctx, port)
	if err != nil {
		t.Fatalf("NewHost with port %d failed: %v", port, err)
	}
	defer host.Close()

	// Verify the host is listening on the specified port
	addrs := host.Addrs()
	foundPort := false
	for _, addr := range addrs {
		addrStr := addr.String()
		if containsPort(addrStr, port) {
			foundPort = true
			break
		}
	}
	if !foundPort {
		t.Errorf("Expected host to listen on port %d, got addrs: %v", port, addrs)
	}
}

func TestHostAddrInfo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	host, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Close()

	addrInfo := host.AddrInfo()

	if addrInfo.ID != host.ID() {
		t.Errorf("AddrInfo.ID = %v, want %v", addrInfo.ID, host.ID())
	}

	if len(addrInfo.Addrs) == 0 {
		t.Error("AddrInfo should have at least one address")
	}
}

func TestHostClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	host, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}

	err = host.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// After close, Host() should still return the underlying host (for inspection)
	// but the host should be closed
	if host.Host() == nil {
		t.Error("Host() should still return the underlying host after close")
	}
}

func TestHostPeersEmpty(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	host, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Close()

	peers := host.Peers()
	if len(peers) != 0 {
		t.Errorf("New host should have no peers, got %d", len(peers))
	}
}

func TestBidirectionalConnection(t *testing.T) {
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

	// Verify host2 sees host1
	if !containsPeer(host2.Peers(), host1.ID()) {
		t.Error("host2 should see host1 as peer")
	}

	// Verify host1 sees host2 (connection is bidirectional in libp2p)
	if !containsPeer(host1.Peers(), host2.ID()) {
		t.Error("host1 should see host2 as peer")
	}
}

// containsPort checks if an address string contains the specified port.
func containsPort(addr string, port int) bool {
	// Simple check: address should end with /tcp/PORT or contain /tcp/PORT/
	portStr := "/tcp/" + itoa(port)
	return contains(addr, portStr)
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// itoa converts int to string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// containsPeer checks if the peer ID is in the list.
func containsPeer(peers []peer.ID, id peer.ID) bool {
	for _, p := range peers {
		if p == id {
			return true
		}
	}
	return false
}

func TestConnectToInvalidPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	host, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Close()

	// Test 1: Empty peer ID
	invalidPeerEmptyID := peer.AddrInfo{
		ID:    "",
		Addrs: []multiaddr.Multiaddr{},
	}
	err = host.Connect(ctx, invalidPeerEmptyID)
	if err == nil {
		t.Error("Connect should fail with empty peer ID")
	}

	// Test 2: No addresses
	invalidPeerNoAddrs := peer.AddrInfo{
		ID:    peer.ID("QmTest"),
		Addrs: []multiaddr.Multiaddr{},
	}
	err = host.Connect(ctx, invalidPeerNoAddrs)
	if err == nil {
		t.Error("Connect should fail with no addresses")
	}
}

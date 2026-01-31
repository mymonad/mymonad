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
	err = host2.Connect(ctx, host1.AddrInfo())
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

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

	err = host2.Connect(ctx, host1.AddrInfo())
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	err = dht1.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("Bootstrap 1 failed: %v", err)
	}

	err = dht2.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("Bootstrap 2 failed: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	// Put a value
	key := "/mymonad/test/key1"
	value := []byte("test-value")

	err = dht1.PutValue(ctx, key, value)
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

func TestDHTProvideAndFindProviders(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

	err = host2.Connect(ctx, host1.AddrInfo())
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	err = dht1.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("Bootstrap 1 failed: %v", err)
	}

	err = dht2.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("Bootstrap 2 failed: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	// Provide a key
	key := "lsh-hash-abc123"
	err = dht1.Provide(ctx, key)
	if err != nil {
		t.Fatalf("Provide failed: %v", err)
	}

	// Give time for provider record to propagate
	time.Sleep(200 * time.Millisecond)

	// Find providers from other node
	providers, err := dht2.FindProviders(ctx, key, 10)
	if err != nil {
		t.Fatalf("FindProviders failed: %v", err)
	}

	// Should find host1 as a provider
	found := false
	for _, p := range providers {
		if p.ID == host1.ID() {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected to find host1 as provider, got providers: %v", providers)
	}
}

func TestDHTClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	host, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Close()

	dht, err := NewDHT(ctx, host)
	if err != nil {
		t.Fatalf("NewDHT failed: %v", err)
	}

	err = dht.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestNewDHTWithNilHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := NewDHT(ctx, nil)
	if err == nil {
		t.Error("NewDHT should fail with nil host")
	}
}

func TestDHTRoutingTableInitiallyEmpty(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	host, err := NewHost(ctx, 0)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Close()

	dht, err := NewDHT(ctx, host)
	if err != nil {
		t.Fatalf("NewDHT failed: %v", err)
	}
	defer dht.Close()

	// Without any connections, routing table should be empty
	rt := dht.RoutingTable()
	if rt == nil {
		t.Fatal("RoutingTable should not be nil")
	}

	peers := rt.ListPeers()
	if len(peers) != 0 {
		t.Errorf("New DHT routing table should be empty, got %d peers", len(peers))
	}
}

func TestMymonadValidatorSelect(t *testing.T) {
	v := mymonadValidator{}

	// Test Select with multiple records - should always return index 0
	records := [][]byte{
		[]byte("record1"),
		[]byte("record2"),
		[]byte("record3"),
	}

	index, err := v.Select("test-key", records)
	if err != nil {
		t.Errorf("Select should not return error, got: %v", err)
	}

	if index != 0 {
		t.Errorf("Select should return 0, got %d", index)
	}

	// Test Select with single record
	singleRecord := [][]byte{[]byte("only-record")}
	index, err = v.Select("another-key", singleRecord)
	if err != nil {
		t.Errorf("Select should not return error, got: %v", err)
	}

	if index != 0 {
		t.Errorf("Select should return 0, got %d", index)
	}
}

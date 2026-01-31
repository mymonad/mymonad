package agent

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/ipfs/go-cid"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	kb "github.com/libp2p/go-libp2p-kbucket"
	record "github.com/libp2p/go-libp2p-record"
	"github.com/libp2p/go-libp2p/core/peer"
	mh "github.com/multiformats/go-multihash"
)

// DHT wraps the Kademlia DHT for distributed peer discovery.
type DHT struct {
	dht *dht.IpfsDHT
}

// mymonadValidator implements record.Validator for the mymonad namespace.
// It accepts any value for keys in the mymonad namespace and always selects
// the first record from a list of candidates. This validator is permissive by design
// since the mymonad protocol trusts the network layer for peer verification rather
// than using record validation for security decisions.
type mymonadValidator struct{}

// Validate always returns nil (accepts all values).
// This is appropriate for the mymonad namespace since peer trustworthiness
// is established through the handshake protocol, not DHT record validation.
func (v mymonadValidator) Validate(_ string, _ []byte) error {
	return nil
}

// Select returns the index of the best record. For simplicity, we always select
// the first record (index 0). In a more sophisticated implementation, this could
// incorporate criteria like peer reputation or record freshness, but for the
// mymonad protocol, the first record is sufficient.
func (v mymonadValidator) Select(_ string, _ [][]byte) (int, error) {
	return 0, nil
}

// NewDHT creates a new Kademlia DHT with the MyMonad protocol prefix.
// The DHT operates in ModeAutoServer mode, acting as both client and server.
func NewDHT(ctx context.Context, host *Host) (*DHT, error) {
	if host == nil {
		return nil, fmt.Errorf("host cannot be nil")
	}

	// Create a namespace validator that accepts "mymonad" keys
	validator := record.NamespacedValidator{
		"mymonad": mymonadValidator{},
	}

	d, err := dht.New(ctx, host.Host(),
		dht.Mode(dht.ModeAutoServer),
		dht.ProtocolPrefix("/mymonad"),
		dht.Validator(validator),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create DHT: %w", err)
	}

	return &DHT{dht: d}, nil
}

// Bootstrap connects to bootstrap peers and refreshes the routing table.
// This should be called after connecting to at least one peer.
func (d *DHT) Bootstrap(ctx context.Context) error {
	return d.dht.Bootstrap(ctx)
}

// RoutingTable returns the DHT routing table for peer discovery.
func (d *DHT) RoutingTable() *kb.RoutingTable {
	return d.dht.RoutingTable()
}

// PutValue stores a value in the DHT under the given key.
// The key must start with a valid namespace (e.g., "/mymonad/").
func (d *DHT) PutValue(ctx context.Context, key string, value []byte) error {
	return d.dht.PutValue(ctx, key, value)
}

// GetValue retrieves a value from the DHT by key.
func (d *DHT) GetValue(ctx context.Context, key string) ([]byte, error) {
	return d.dht.GetValue(ctx, key)
}

// Provide announces that this node can provide content identified by key.
// This is used for content-addressed peer discovery (e.g., LSH hash publishing).
func (d *DHT) Provide(ctx context.Context, key string) error {
	c, err := makeCID(key)
	if err != nil {
		return fmt.Errorf("failed to create CID for key %q: %w", key, err)
	}
	return d.dht.Provide(ctx, c, true)
}

// FindProviders finds nodes that have announced they can provide content for key.
// Returns up to count providers.
func (d *DHT) FindProviders(ctx context.Context, key string, count int) ([]peer.AddrInfo, error) {
	c, err := makeCID(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create CID for key %q: %w", key, err)
	}
	peerChan := d.dht.FindProvidersAsync(ctx, c, count)

	var providers []peer.AddrInfo
	for p := range peerChan {
		if p.ID != "" {
			providers = append(providers, p)
		}
	}

	return providers, nil
}

// Close shuts down the DHT.
func (d *DHT) Close() error {
	return d.dht.Close()
}

// makeCID creates a CID from a string key for use with provider records.
func makeCID(key string) (cid.Cid, error) {
	h := sha256.Sum256([]byte(key))
	mhash, err := mh.Encode(h[:], mh.SHA2_256)
	if err != nil {
		return cid.Cid{}, fmt.Errorf("failed to encode multihash: %w", err)
	}
	return cid.NewCidV1(cid.Raw, mhash), nil
}

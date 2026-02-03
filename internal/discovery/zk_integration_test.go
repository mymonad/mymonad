// Package discovery provides peer discovery mechanisms for the P2P network.
// This file tests ZK service integration with the discovery Manager.
package discovery

import (
	"log/slog"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mymonad/mymonad/internal/zkproof"
)

// mockZKService is a mock ZK service for testing.
// We use a real disabled ZKService for most tests, but this allows
// testing edge cases.
type mockZKService struct {
	enabled  bool
	requires bool
	prefers  bool
}

// TestShouldRequireZK_WithMockService tests the full ShouldRequireZK logic
// using mock service configurations.
func TestShouldRequireZK_WithMockService(t *testing.T) {
	// Create a disabled ZK service (default config)
	disabledConfig := zkproof.DefaultZKConfig()
	disabledConfig.Enabled = false
	disabledSvc, err := zkproof.NewZKService(disabledConfig)
	if err != nil {
		t.Fatalf("Failed to create disabled ZK service: %v", err)
	}

	// Create test peer ID
	peerID, err := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	if err != nil {
		t.Fatalf("Failed to decode peer ID: %v", err)
	}

	tests := []struct {
		name       string
		zkService  *zkproof.ZKService
		peerRecord *BucketRecord
		want       ZKRequirementResult
	}{
		{
			name:      "nil service - peer with ZK",
			zkService: nil,
			peerRecord: &BucketRecord{
				PeerID:       peerID,
				ZKCapability: NewZKCapability(),
			},
			want: ZKNotRequired,
		},
		{
			name:      "disabled service - peer with ZK",
			zkService: disabledSvc,
			peerRecord: &BucketRecord{
				PeerID:       peerID,
				ZKCapability: NewZKCapability(),
			},
			want: ZKNotRequired,
		},
		{
			name:      "disabled service - peer without ZK",
			zkService: disabledSvc,
			peerRecord: &BucketRecord{
				PeerID:       peerID,
				ZKCapability: nil,
			},
			want: ZKNotRequired,
		},
		{
			name:       "nil record",
			zkService:  nil,
			peerRecord: nil,
			want:       ZKNotRequired,
		},
		{
			name:      "peer with unsupported ZK",
			zkService: disabledSvc,
			peerRecord: &BucketRecord{
				PeerID: peerID,
				ZKCapability: &ZKCapability{
					Supported:        false,
					ProofSystem:      "plonk-bn254",
					MaxSignatureBits: 256,
				},
			},
			want: ZKNotRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewManagerWithLogger(ManagerConfig{}, slog.Default())
			m.SetZKService(tt.zkService)

			got := m.ShouldRequireZK(tt.peerRecord)
			if got != tt.want {
				t.Errorf("ShouldRequireZK() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCreateLocalZKCapability_Consistency tests that the local ZK capability
// matches the expected values from the zkproof package.
func TestCreateLocalZKCapability_Consistency(t *testing.T) {
	// When ZK is not enabled, capability should be nil
	m := NewManager(ManagerConfig{})
	cap := m.CreateLocalZKCapability()
	if cap != nil {
		t.Error("CreateLocalZKCapability should return nil when ZK service is not set")
	}

	// Verify that NewZKCapability returns consistent values
	dhtCap := NewZKCapability()
	if dhtCap.ProofSystem != zkproof.SupportedProofSystem {
		t.Errorf("DHT ZKCapability.ProofSystem = %q, want %q",
			dhtCap.ProofSystem, zkproof.SupportedProofSystem)
	}

	if dhtCap.MaxSignatureBits != zkproof.SupportedSignatureBits {
		t.Errorf("DHT ZKCapability.MaxSignatureBits = %d, want %d",
			dhtCap.MaxSignatureBits, zkproof.SupportedSignatureBits)
	}
}

// TestZKCapability_FromZKProofPackage tests compatibility between
// discovery.ZKCapability and zkproof.ZKCapability.
func TestZKCapability_FromZKProofPackage(t *testing.T) {
	// Create capability from zkproof package
	zkCap := zkproof.NewZKCapability()

	// Create capability from discovery package
	dhtCap := NewZKCapability()

	// They should have matching values
	if dhtCap.Supported != zkCap.Supported {
		t.Errorf("Supported mismatch: DHT=%v, ZK=%v", dhtCap.Supported, zkCap.Supported)
	}

	if dhtCap.ProofSystem != zkCap.ProofSystem {
		t.Errorf("ProofSystem mismatch: DHT=%q, ZK=%q", dhtCap.ProofSystem, zkCap.ProofSystem)
	}

	if dhtCap.MaxSignatureBits != zkCap.MaxSignatureBits {
		t.Errorf("MaxSignatureBits mismatch: DHT=%d, ZK=%d",
			dhtCap.MaxSignatureBits, zkCap.MaxSignatureBits)
	}
}

// TestBucketRecord_ZKCapability_RoundTrip tests that ZK capability survives
// a full serialization round-trip.
func TestBucketRecord_ZKCapability_RoundTrip(t *testing.T) {
	peerID, err := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	if err != nil {
		t.Fatalf("Failed to decode peer ID: %v", err)
	}

	tests := []struct {
		name string
		cap  *ZKCapability
	}{
		{
			name: "nil capability",
			cap:  nil,
		},
		{
			name: "standard capability",
			cap:  NewZKCapability(),
		},
		{
			name: "custom proof system",
			cap: &ZKCapability{
				Supported:        true,
				ProofSystem:      "groth16-bn254",
				MaxSignatureBits: 128,
			},
		},
		{
			name: "disabled capability",
			cap: &ZKCapability{
				Supported:        false,
				ProofSystem:      "plonk-bn254",
				MaxSignatureBits: 256,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := &BucketRecord{
				PeerID:       peerID,
				Addresses:    []string{"/ip4/192.168.1.1/tcp/4001"},
				Timestamp:    1234567890,
				TTL:          3600,
				ZKCapability: tt.cap,
			}

			// Serialize
			data, err := BucketRecordToJSON(original)
			if err != nil {
				t.Fatalf("BucketRecordToJSON failed: %v", err)
			}

			// Deserialize
			parsed, err := BucketRecordFromJSON(data)
			if err != nil {
				t.Fatalf("BucketRecordFromJSON failed: %v", err)
			}

			// Compare
			if tt.cap == nil {
				if parsed.ZKCapability != nil {
					t.Error("Expected nil ZKCapability after round-trip")
				}
			} else {
				if parsed.ZKCapability == nil {
					t.Fatal("ZKCapability should not be nil after round-trip")
				}
				if parsed.ZKCapability.Supported != tt.cap.Supported {
					t.Errorf("Supported mismatch: got %v, want %v",
						parsed.ZKCapability.Supported, tt.cap.Supported)
				}
				if parsed.ZKCapability.ProofSystem != tt.cap.ProofSystem {
					t.Errorf("ProofSystem mismatch: got %q, want %q",
						parsed.ZKCapability.ProofSystem, tt.cap.ProofSystem)
				}
				if parsed.ZKCapability.MaxSignatureBits != tt.cap.MaxSignatureBits {
					t.Errorf("MaxSignatureBits mismatch: got %d, want %d",
						parsed.ZKCapability.MaxSignatureBits, tt.cap.MaxSignatureBits)
				}
			}
		})
	}
}

// TestZKRequirementResult_String tests that ZKRequirementResult values
// behave as expected in comparisons.
func TestZKRequirementResult_String(t *testing.T) {
	results := []struct {
		result ZKRequirementResult
		name   string
	}{
		{ZKNotRequired, "ZKNotRequired"},
		{ZKRequired, "ZKRequired"},
		{ZKSkipPeer, "ZKSkipPeer"},
	}

	// Verify each result has a unique value
	seen := make(map[ZKRequirementResult]bool)
	for _, r := range results {
		if seen[r.result] {
			t.Errorf("Duplicate ZKRequirementResult value for %s", r.name)
		}
		seen[r.result] = true
	}

	// Verify ZKNotRequired is the zero value
	var zero ZKRequirementResult
	if zero != ZKNotRequired {
		t.Error("ZKNotRequired should be the zero value of ZKRequirementResult")
	}
}

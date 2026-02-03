# LSH Discovery Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable privacy-preserving peer discovery using Locality Sensitive Hashing with a commitment scheme to prevent signature crafting attacks.

**Architecture:** Hybrid approach combining DHT bucket publishing for coarse discovery with a dedicated protocol for secure signature exchange via commit-reveal scheme.

**Tech Stack:** libp2p (DHT, streams), SHA-256 (commitments), Protocol Buffers (messages)

---

## 1. Overview

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        LSH Discovery System                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │   Ingest     │───▶│  Discovery   │───▶│  Handshake   │              │
│  │   Daemon     │    │   Manager    │    │   Manager    │              │
│  └──────────────┘    └──────────────┘    └──────────────┘              │
│         │                   │                   │                       │
│         │ IPC: MonadUpdated │                   │                       │
│         ▼                   ▼                   ▼                       │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │    Monad     │    │  Kademlia    │    │   Stream     │              │
│  │   Vector     │    │    DHT       │    │   Handler    │              │
│  └──────────────┘    └──────────────┘    └──────────────┘              │
│                             │                   │                       │
│                             │ Bucket ID         │ /mymonad/discovery/   │
│                             ▼                   ▼        1.0.0          │
│                      ┌─────────────────────────────┐                    │
│                      │      P2P Network Layer      │                    │
│                      │   (libp2p + mDNS + DHT)     │                    │
│                      └─────────────────────────────┘                    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Discovery Method | Hybrid (DHT + Protocol) | DHT for coarse bucket matching, protocol for secure exchange |
| Privacy Model | Commitment Scheme | SHA-256(signature \|\| salt) prevents signature crafting attacks |
| Initiation Policy | Lower Peer ID | Deterministic, prevents duplicate streams |
| Rate Limiting | Threshold + Rate | <25% Hamming + 1/minute prevents spam |
| Signature Lifecycle | On Update + TTL | ΔMonad > ε triggers regeneration |

### Stage 0: Pre-filtering

Discovery acts as **Stage 0** before the expensive handshake protocol:

```
Discovery (cheap)  →  Handshake Stage 1-5 (expensive PoW)
   LSH match?            Full protocol
```

Only peers passing the LSH similarity threshold proceed to handshake.

---

## 2. Protocol Flow

### Message Sequence

```
    Alice (Lower PeerID)                    Bob (Higher PeerID)
           │                                       │
           │◀─────── DHT: Same Bucket ID ─────────▶│
           │                                       │
           │  ──── Open /mymonad/discovery/1.0.0 ────▶
           │                                       │
           │  ──── DiscoveryCommit ─────────────────▶
           │       {commitment_A, timestamp, peer_id}
           │                                       │
           │  ◀─── DiscoveryCommit ─────────────────
           │       {commitment_B, timestamp, peer_id}
           │                                       │
           │  ──── DiscoveryReveal ─────────────────▶
           │       {signature_A, salt_A}
           │                                       │
           │       [Bob verifies: SHA-256(sig_A||salt_A) == commitment_A]
           │                                       │
           │  ◀─── DiscoveryReveal ─────────────────
           │       {signature_B, salt_B}
           │                                       │
           │       [Alice verifies: SHA-256(sig_B||salt_B) == commitment_B]
           │                                       │
           │  [Both compute Hamming distance]      │
           │  [If < threshold: initiate handshake] │
           │                                       │
```

### Protocol Buffer Definitions

```protobuf
// api/proto/discovery.proto

syntax = "proto3";
package mymonad.discovery;

option go_package = "github.com/mymonad/mymonad/api/proto/discovery";

// DiscoveryCommit is sent first by both parties
message DiscoveryCommit {
  bytes commitment = 1;    // SHA-256(signature || salt), 32 bytes
  int64 timestamp = 2;     // Unix milliseconds, for replay protection (±5s window)
  bytes peer_id = 3;       // Sender's libp2p peer ID
}

// DiscoveryReveal is sent after both commits are exchanged
message DiscoveryReveal {
  bytes signature = 1;     // Full LSH signature (N bits, typically 256)
  bytes salt = 2;          // Random salt used in commitment (minimum 16 bytes, high-entropy)
}

// DiscoveryReject indicates protocol failure
message DiscoveryReject {
  string reason = 1;       // "commitment_mismatch", "stale_timestamp", "invalid_salt", "malformed_signature"
}
```

### Validation Requirements

| Field | Requirement |
|-------|-------------|
| `timestamp` | Within ±5 seconds of local time |
| `salt` | Minimum 16 bytes, cryptographically random |
| `signature` | Exact expected length (e.g., 32 bytes for 256-bit LSH) |
| `commitment` | SHA-256 output, 32 bytes |

---

## 3. DHT Integration & Signature Lifecycle

### Bucket ID Derivation

```go
// pkg/lsh/bucket.go

const (
    BucketIDBits = 8  // 256 possible buckets
)

// DeriveBucketID extracts the first N bits of the LSH signature
// to form a coarse "bucket" for DHT-based discovery.
func DeriveBucketID(signature []byte) string {
    if len(signature) == 0 {
        return ""
    }
    // Use first byte as bucket ID (256 buckets)
    return fmt.Sprintf("/mymonad/lsh/bucket/%02x", signature[0])
}
```

### DHT Record Structure

```go
// internal/discovery/dht.go

type BucketRecord struct {
    PeerID    peer.ID   `json:"peer_id"`
    Addresses []string  `json:"addrs"`      // Multiaddrs for direct connection
    Timestamp int64     `json:"timestamp"`  // For freshness/expiry
    TTL       int64     `json:"ttl"`        // Seconds until stale
}

func (dm *DiscoveryManager) PublishToBucket(ctx context.Context) error {
    bucketID := lsh.DeriveBucketID(dm.localSignature)

    record := BucketRecord{
        PeerID:    dm.host.ID(),
        Addresses: multiaddrsToStrings(dm.host.Addrs()),
        Timestamp: time.Now().Unix(),
        TTL:       3600,  // 1 hour
    }

    data, _ := json.Marshal(record)
    return dm.dht.PutValue(ctx, bucketID, data)
}
```

### Signature Lifecycle

```go
// internal/discovery/lifecycle.go

const (
    SignatureTTL       = 1 * time.Hour
    RepublishBuffer    = 5 * time.Minute
    MinMonadDelta      = 0.01  // ε threshold for regeneration
)

type SignatureState struct {
    Signature    []byte
    GeneratedAt  time.Time
    PublishedAt  time.Time
    MonadHash    []byte  // Hash of Monad at generation time
}

// ShouldRegenerate returns true if signature needs regeneration
func (s *SignatureState) ShouldRegenerate(currentMonad *monad.Monad) bool {
    // Regenerate if Monad changed significantly
    currentHash := currentMonad.Hash()
    if !bytes.Equal(s.MonadHash, currentHash) {
        delta := currentMonad.DeltaFrom(s.MonadHash)
        if delta > MinMonadDelta {
            return true
        }
    }
    return false
}

// ShouldRepublish returns true if DHT record needs refresh
func (s *SignatureState) ShouldRepublish() bool {
    return time.Since(s.PublishedAt) > (SignatureTTL - RepublishBuffer)
}
```

### IPC Notification Flow

```go
// cmd/mymonad-agent/daemon.go

func (d *Daemon) handleMonadUpdated(newMonad *monad.Monad) {
    // Notify discovery manager of Monad change
    if d.discoveryMgr.ShouldRegenerateSignature(newMonad) {
        d.discoveryMgr.RegenerateSignature(newMonad)
        d.discoveryMgr.PublishToBucket(context.Background())
    }
}
```

---

## 4. Discovery Manager & Rate Limiting

### Core Structure

```go
// internal/discovery/manager.go

type DiscoveryConfig struct {
    HammingThreshold    int           // Max Hamming distance (default: 25% of bits)
    InitiationRateLimit time.Duration // Min time between handshake initiations (default: 1 minute)
    ExchangeTimeout     time.Duration // Max time for commit-reveal exchange (default: 30s)
    MaxPendingExchanges int           // Limit concurrent exchanges (default: 10)
}

type DiscoveryManager struct {
    mu               sync.RWMutex
    localSignature   []byte
    signatureState   *SignatureState
    discoveredPeers  map[peer.ID]*DiscoveredPeer
    pendingExchanges map[peer.ID]*Exchange
    lastInitiation   time.Time

    dht              *dht.IpfsDHT
    host             host.Host
    handshakeMgr     *handshake.Manager
    config           DiscoveryConfig
}

type DiscoveredPeer struct {
    PeerID          peer.ID
    Signature       []byte
    HammingDistance int
    DiscoveredAt    time.Time
    LastExchange    time.Time
}
```

### Rate Limiting Logic

```go
// Handshake initiation is rate-limited to prevent spam
func (dm *DiscoveryManager) canInitiateHandshake() bool {
    dm.mu.RLock()
    defer dm.mu.RUnlock()
    return time.Since(dm.lastInitiation) >= dm.config.InitiationRateLimit
}

func (dm *DiscoveryManager) recordHandshakeInitiation() {
    dm.mu.Lock()
    dm.lastInitiation = time.Now()
    dm.mu.Unlock()
}

// MaybeInitiateHandshake checks threshold and rate limit before starting handshake
func (dm *DiscoveryManager) MaybeInitiateHandshake(peer *DiscoveredPeer) error {
    // Check Hamming threshold
    if peer.HammingDistance > dm.config.HammingThreshold {
        return nil  // Not similar enough, skip silently
    }

    // Check rate limit
    if !dm.canInitiateHandshake() {
        return nil  // Rate limited, skip silently
    }

    // Initiate handshake
    dm.recordHandshakeInitiation()
    return dm.handshakeMgr.InitiateHandshake(peer.PeerID)
}
```

### Discovery Loop

```go
func (dm *DiscoveryManager) discoveryLoop(ctx context.Context) {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            dm.discoverBucketPeers(ctx)
        }
    }
}

func (dm *DiscoveryManager) discoverBucketPeers(ctx context.Context) {
    bucketID := lsh.DeriveBucketID(dm.localSignature)

    // Query DHT for peers in same bucket
    records, err := dm.dht.GetValues(ctx, bucketID, 20)
    if err != nil {
        slog.Warn("failed to query bucket", "bucket", bucketID, "error", err)
        return
    }

    for _, record := range records {
        var br BucketRecord
        if err := json.Unmarshal(record, &br); err != nil {
            continue
        }

        // Skip self
        if br.PeerID == dm.host.ID() {
            continue
        }

        // Skip already discovered
        if _, exists := dm.discoveredPeers[br.PeerID]; exists {
            continue
        }

        // Initiate signature exchange
        go dm.initiateExchange(ctx, br.PeerID)
    }
}
```

---

## 5. Error Handling & Edge Cases

### Protocol-Level Errors

```go
type DiscoveryError string

const (
    ErrCommitmentMismatch DiscoveryError = "commitment_mismatch"   // SHA-256 verification failed
    ErrStaleTimestamp     DiscoveryError = "stale_timestamp"       // Outside ±5s window
    ErrInvalidSalt        DiscoveryError = "invalid_salt"          // Salt < 16 bytes
    ErrMalformedSignature DiscoveryError = "malformed_signature"   // Signature wrong length
    ErrRateLimited        DiscoveryError = "rate_limited"          // Too many exchanges
)
```

### Error Response Flow

| Error | Response | Action | Retry |
|-------|----------|--------|-------|
| Commitment mismatch | `DiscoveryReject{reason: "commitment_mismatch"}` | Close stream, log warning | No |
| Stale timestamp | `DiscoveryReject{reason: "stale_timestamp"}` | Close stream | Yes (fresh timestamp) |
| Invalid salt | `DiscoveryReject{reason: "invalid_salt"}` | Close stream, log warning | No |
| Malformed signature | `DiscoveryReject{reason: "malformed_signature"}` | Close stream, log error | No (protocol violation) |
| Rate limited | `DiscoveryReject{reason: "rate_limited"}` | Close stream | Yes (backoff) |
| Stream timeout | N/A | Close stream after 30s | Yes (backoff) |
| Peer disconnected | N/A | Clean up pending exchange | Yes (backoff) |

### Exchange Struct with Signature Snapshot

```go
// Exchange captures immutable state at commit generation time
type Exchange struct {
    PeerID           peer.ID
    Role             ExchangeRole      // Initiator or Responder
    State            ExchangeState     // Pending, CommitSent, RevealSent, Complete, Failed

    // Snapshot: captured at commit generation, immutable for exchange lifetime
    SignatureSnapshot []byte           // Local signature at commit time
    Salt              []byte           // Random salt for this exchange
    Commitment        []byte           // SHA-256(SignatureSnapshot || Salt)

    // Peer data (populated on receive)
    PeerCommitment    []byte
    PeerSignature     []byte
    PeerSalt          []byte

    // Timing
    CreatedAt         time.Time
    ExpiresAt         time.Time        // CreatedAt + 30s
    RetryCount        int
}

// NewExchange snapshots the current signature atomically
func (dm *DiscoveryManager) NewExchange(peerID peer.ID, role ExchangeRole) (*Exchange, error) {
    dm.mu.RLock()
    signatureSnapshot := make([]byte, len(dm.localSignature))
    copy(signatureSnapshot, dm.localSignature)
    dm.mu.RUnlock()

    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return nil, fmt.Errorf("generate salt: %w", err)
    }

    commitment := computeCommitment(signatureSnapshot, salt)

    return &Exchange{
        PeerID:            peerID,
        Role:              role,
        State:             ExchangeStatePending,
        SignatureSnapshot: signatureSnapshot,
        Salt:              salt,
        Commitment:        commitment,
        CreatedAt:         time.Now(),
        ExpiresAt:         time.Now().Add(30 * time.Second),
    }, nil
}
```

### Complete Retry Logic

```go
const (
    MaxExchangeRetries = 3
    RetryBackoffBase   = 5 * time.Second
    RetryBackoffMax    = 60 * time.Second
)

func (dm *DiscoveryManager) shouldRetry(peerID peer.ID, err DiscoveryError) bool {
    switch err {
    case ErrCommitmentMismatch:
        return false  // Verification failed, likely tampering
    case ErrInvalidSalt:
        return false  // Protocol violation
    case ErrMalformedSignature:
        return false  // Protocol violation or incompatible version
    case ErrStaleTimestamp:
        return true   // Clock skew, retry with fresh timestamp
    case ErrRateLimited:
        return true   // Backoff and retry later
    default:
        return false  // Unknown errors are not retried
    }
}

func (dm *DiscoveryManager) retryBackoff(retryCount int) time.Duration {
    backoff := RetryBackoffBase * time.Duration(1<<retryCount)
    if backoff > RetryBackoffMax {
        return RetryBackoffMax
    }
    return backoff
}
```

### Edge Cases

1. **Simultaneous Exchange Attempts**: Lower Peer ID rule prevents this; if both somehow open streams, the higher Peer ID immediately closes theirs.

2. **Signature Changes Mid-Exchange**: The `Exchange.SignatureSnapshot` is captured atomically at `NewExchange()` time. The Reveal stage always uses this snapshot, guaranteeing `Commitment = SHA-256(SignatureSnapshot || Salt)` regardless of concurrent Monad updates.

3. **DHT Partition**: If unable to publish to DHT, continue with existing bucket peers; log warning and retry publication with exponential backoff.

4. **Exchange Expiration**: Exchanges older than 30s are garbage-collected. If peer reconnects, a fresh exchange with new snapshot and salt is initiated.

---

## 6. Testing Strategy

### Unit Tests: Discovery State Machine

```go
// internal/discovery/exchange_test.go

func TestExchange_CommitmentVerification(t *testing.T) {
    tests := []struct {
        name      string
        signature []byte
        salt      []byte
        tamper    func([]byte) []byte  // Modify commitment before verify
        wantErr   DiscoveryError
    }{
        {
            name:      "valid commitment",
            signature: makeSignature(256),
            salt:      makeSalt(16),
            tamper:    nil,
            wantErr:   "",
        },
        {
            name:      "tampered commitment",
            signature: makeSignature(256),
            salt:      makeSalt(16),
            tamper:    func(c []byte) []byte { c[0] ^= 0xFF; return c },
            wantErr:   ErrCommitmentMismatch,
        },
        {
            name:      "salt too short",
            signature: makeSignature(256),
            salt:      makeSalt(8),  // < 16 bytes
            tamper:    nil,
            wantErr:   ErrInvalidSalt,
        },
        {
            name:      "malformed signature length",
            signature: makeSignature(128),  // Wrong bit count
            salt:      makeSalt(16),
            tamper:    nil,
            wantErr:   ErrMalformedSignature,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            commitment := computeCommitment(tt.signature, tt.salt)
            if tt.tamper != nil {
                commitment = tt.tamper(commitment)
            }

            err := verifyCommitment(commitment, tt.signature, tt.salt)

            if tt.wantErr == "" {
                require.NoError(t, err)
            } else {
                require.ErrorIs(t, err, tt.wantErr)
            }
        })
    }
}

func TestExchange_TimestampValidation(t *testing.T) {
    tests := []struct {
        name    string
        offset  time.Duration
        wantErr DiscoveryError
    }{
        {"within window (0s)", 0, ""},
        {"within window (+4s)", 4 * time.Second, ""},
        {"within window (-4s)", -4 * time.Second, ""},
        {"stale future (+6s)", 6 * time.Second, ErrStaleTimestamp},
        {"stale past (-6s)", -6 * time.Second, ErrStaleTimestamp},
        {"edge case (+5s)", 5 * time.Second, ""},
        {"edge case (-5s)", -5 * time.Second, ""},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            timestamp := time.Now().Add(tt.offset).UnixMilli()
            err := validateTimestamp(timestamp)

            if tt.wantErr == "" {
                require.NoError(t, err)
            } else {
                require.ErrorIs(t, err, tt.wantErr)
            }
        })
    }
}

func TestExchange_SignatureSnapshot_Immutable(t *testing.T) {
    dm := newTestDiscoveryManager()
    dm.SetLocalSignature(makeSignature(256))

    // Create exchange, capturing snapshot
    exchange, err := dm.NewExchange(testPeerID, RoleInitiator)
    require.NoError(t, err)

    originalSnapshot := make([]byte, len(exchange.SignatureSnapshot))
    copy(originalSnapshot, exchange.SignatureSnapshot)

    // Simulate Monad update mid-exchange
    dm.SetLocalSignature(makeSignature(256))  // Different signature

    // Snapshot must remain unchanged
    require.Equal(t, originalSnapshot, exchange.SignatureSnapshot)

    // Commitment must still verify against snapshot
    err = verifyCommitment(exchange.Commitment, exchange.SignatureSnapshot, exchange.Salt)
    require.NoError(t, err)
}
```

### Unit Tests: Retry Logic

```go
// internal/discovery/manager_test.go

func TestDiscoveryManager_ShouldRetry(t *testing.T) {
    dm := newTestDiscoveryManager()

    tests := []struct {
        err       DiscoveryError
        wantRetry bool
    }{
        {ErrCommitmentMismatch, false},
        {ErrInvalidSalt, false},
        {ErrMalformedSignature, false},
        {ErrStaleTimestamp, true},
        {ErrRateLimited, true},
        {DiscoveryError("unknown"), false},
    }

    for _, tt := range tests {
        t.Run(string(tt.err), func(t *testing.T) {
            got := dm.shouldRetry(testPeerID, tt.err)
            require.Equal(t, tt.wantRetry, got)
        })
    }
}

func TestDiscoveryManager_RetryBackoff(t *testing.T) {
    dm := newTestDiscoveryManager()

    require.Equal(t, 5*time.Second, dm.retryBackoff(0))
    require.Equal(t, 10*time.Second, dm.retryBackoff(1))
    require.Equal(t, 20*time.Second, dm.retryBackoff(2))
    require.Equal(t, 40*time.Second, dm.retryBackoff(3))
    require.Equal(t, 60*time.Second, dm.retryBackoff(4))  // Capped
    require.Equal(t, 60*time.Second, dm.retryBackoff(10)) // Still capped
}
```

### Unit Tests: Rate Limiting & Initiation

```go
func TestDiscoveryManager_RateLimit(t *testing.T) {
    dm := newTestDiscoveryManager()
    dm.config.InitiationRateLimit = time.Minute

    // First initiation allowed
    allowed := dm.canInitiateHandshake()
    require.True(t, allowed)
    dm.recordHandshakeInitiation()

    // Immediate second attempt blocked
    allowed = dm.canInitiateHandshake()
    require.False(t, allowed)

    // After rate limit window, allowed again
    dm.lastInitiation = time.Now().Add(-61 * time.Second)
    allowed = dm.canInitiateHandshake()
    require.True(t, allowed)
}

func TestDiscoveryManager_LowerPeerIDInitiates(t *testing.T) {
    localID := peer.ID("AAAA")   // Lower
    remoteID := peer.ID("ZZZZ")  // Higher

    require.True(t, shouldInitiate(localID, remoteID))
    require.False(t, shouldInitiate(remoteID, localID))
}
```

### Integration Tests: Full Exchange Flow

```go
// tests/discovery_integration_test.go

func TestDiscovery_FullExchangeFlow(t *testing.T) {
    // Create two discovery managers with mock DHT
    alice := newTestDiscoveryManager()
    bob := newTestDiscoveryManager()

    aliceSig := makeSignature(256)
    bobSig := makeSimilarSignature(aliceSig, 20)  // 20% Hamming distance

    alice.SetLocalSignature(aliceSig)
    bob.SetLocalSignature(bobSig)

    // Simulate stream connection (lower peer ID initiates)
    stream := newMockStream(alice.host.ID(), bob.host.ID())

    // Alice sends commit
    exchange, _ := alice.NewExchange(bob.host.ID(), RoleInitiator)
    commitMsg := &DiscoveryCommit{
        Commitment: exchange.Commitment,
        Timestamp:  time.Now().UnixMilli(),
        PeerId:     []byte(alice.host.ID()),
    }

    // Bob receives commit, sends own commit
    bobExchange, _ := bob.handleCommit(stream, commitMsg)
    require.NotNil(t, bobExchange)

    // Alice receives Bob's commit, sends reveal
    // Bob receives reveal, verifies, sends own reveal
    // Alice receives reveal, verifies

    // Both should have valid peer signatures
    require.Equal(t, bobSig, exchange.PeerSignature)
    require.Equal(t, aliceSig, bobExchange.PeerSignature)

    // Hamming distance should qualify for handshake
    distance := hammingDistance(aliceSig, bobSig)
    require.Less(t, distance, 25)  // < 25% threshold
}

func TestDiscovery_RejectMaliciousPeer(t *testing.T) {
    alice := newTestDiscoveryManager()
    mallory := newTestDiscoveryManager()

    // Mallory sends valid commit but tampered reveal
    exchange, _ := mallory.NewExchange(alice.host.ID(), RoleInitiator)
    commitMsg := &DiscoveryCommit{
        Commitment: exchange.Commitment,
        Timestamp:  time.Now().UnixMilli(),
        PeerId:     []byte(mallory.host.ID()),
    }

    aliceExchange, _ := alice.handleCommit(newMockStream(), commitMsg)

    // Mallory sends different signature than committed
    tamperedReveal := &DiscoveryReveal{
        Signature: makeSignature(256),  // Different from snapshot
        Salt:      exchange.Salt,
    }

    err := alice.handleReveal(aliceExchange, tamperedReveal)
    require.ErrorIs(t, err, ErrCommitmentMismatch)
}
```

### Test Coverage Targets

| Component | Target | Focus Areas |
|-----------|--------|-------------|
| `exchange.go` | 90% | Commitment generation, verification, state transitions |
| `manager.go` | 85% | Rate limiting, retry logic, peer management |
| `protocol.go` | 85% | Message handling, stream management, error responses |
| Integration | N/A | Full exchange flow, adversarial scenarios |

---

## 7. Implementation Tasks

### Task 1: Protocol Buffer Definitions

**Files:**
- Create: `api/proto/discovery.proto`

**Steps:**
1. Write protobuf definitions for DiscoveryCommit, DiscoveryReveal, DiscoveryReject
2. Run `make proto` to generate Go code
3. Commit

### Task 2: LSH Bucket Derivation

**Files:**
- Create: `pkg/lsh/bucket.go`
- Create: `pkg/lsh/bucket_test.go`

**Steps:**
1. Write failing test for DeriveBucketID
2. Implement DeriveBucketID function
3. Write tests for edge cases (empty signature, various lengths)
4. Commit

### Task 3: Commitment Scheme

**Files:**
- Create: `internal/discovery/commitment.go`
- Create: `internal/discovery/commitment_test.go`

**Steps:**
1. Write failing tests for computeCommitment and verifyCommitment
2. Implement SHA-256(signature || salt) commitment
3. Write tests for validation (salt length, signature length)
4. Commit

### Task 4: Exchange State Machine

**Files:**
- Create: `internal/discovery/exchange.go`
- Create: `internal/discovery/exchange_test.go`

**Steps:**
1. Define Exchange struct with SignatureSnapshot
2. Write failing tests for NewExchange, state transitions
3. Implement Exchange creation with atomic snapshot
4. Write tests for snapshot immutability
5. Commit

### Task 5: Discovery Manager Core

**Files:**
- Create: `internal/discovery/manager.go`
- Create: `internal/discovery/manager_test.go`

**Steps:**
1. Define DiscoveryManager struct and DiscoveryConfig
2. Write failing tests for rate limiting
3. Implement canInitiateHandshake, recordHandshakeInitiation
4. Write tests for retry logic
5. Implement shouldRetry, retryBackoff
6. Commit

### Task 6: DHT Integration

**Files:**
- Create: `internal/discovery/dht.go`
- Create: `internal/discovery/dht_test.go`

**Steps:**
1. Define BucketRecord struct
2. Write failing tests for PublishToBucket
3. Implement DHT publish/query
4. Write tests for signature lifecycle
5. Implement ShouldRegenerate, ShouldRepublish
6. Commit

### Task 7: Protocol Stream Handler

**Files:**
- Create: `internal/discovery/protocol.go`
- Create: `internal/discovery/protocol_test.go`

**Steps:**
1. Register `/mymonad/discovery/1.0.0` stream handler
2. Write failing tests for handleCommit, handleReveal
3. Implement commit-reveal exchange flow
4. Write tests for error responses
5. Implement DiscoveryReject handling
6. Commit

### Task 8: Discovery Loop

**Files:**
- Modify: `internal/discovery/manager.go`

**Steps:**
1. Write failing tests for discoveryLoop
2. Implement periodic bucket peer discovery
3. Write tests for exchange initiation (lower peer ID rule)
4. Implement initiateExchange with peer ID comparison
5. Commit

### Task 9: Agent Integration

**Files:**
- Modify: `cmd/mymonad-agent/daemon.go`
- Modify: `internal/agent/agent.go`

**Steps:**
1. Initialize DiscoveryManager in daemon
2. Wire up IPC MonadUpdated notification
3. Start discovery loop on agent start
4. Commit

### Task 10: Integration Tests

**Files:**
- Create: `tests/discovery_integration_test.go`

**Steps:**
1. Write full exchange flow test (Alice + Bob)
2. Write adversarial test (Mallory tampered reveal)
3. Write DHT partition test
4. Write concurrent exchange test
5. Commit

---

## 8. Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Signature crafting | Commitment scheme: must commit before seeing peer's signature |
| Replay attacks | Timestamp validation (±5s window) |
| Correlation attacks | LSH only reveals coarse similarity, not raw vectors |
| Spam/DoS | Rate limiting (1/minute handshake initiation) |
| Man-in-the-middle | libp2p transport encryption + peer ID verification |

### Privacy Guarantees

1. **Raw vectors never transmitted**: Only LSH signatures and commitments
2. **Commitments hide signatures**: SHA-256 is preimage-resistant
3. **Bucket membership is coarse**: 256 buckets means ~0.4% of network per bucket
4. **Failed exchanges reveal nothing**: Commitment verified before signature revealed

---

## 9. Future Enhancements

1. **Adaptive Thresholds**: Adjust Hamming threshold based on network density
2. **Reputation Integration**: Factor peer reputation into discovery priority
3. **Multi-Bucket Publishing**: Publish to multiple nearby buckets for redundancy
4. **Signature Blinding**: Additional privacy layer using blinding factors

# Handshake Protocol Implementation Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire the existing protocol state machine to libp2p streams, enabling automated peer matching with CLI override capability.

**Architecture:** Three-layer design (CLI → Session Manager → libp2p streams) with pull-based human notification and async approval.

**Tech Stack:** Go, libp2p streams, protobuf wire format, gRPC for CLI integration.

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    CLI Layer                             │
│  mymonad-cli handshake start <peer-id>                  │
│  mymonad-cli handshake list / watch / approve / reject  │
└─────────────────────────────────────────────────────────┘
                          │ gRPC (Unix socket / WireGuard)
┌─────────────────────────────────────────────────────────┐
│                 Session Manager                          │
│  - Tracks active handshakes (map[sessionID]*Session)    │
│  - Auto-initiates based on peer discovery               │
│  - Exposes pending approvals via gRPC (pull model)      │
│  - Handles cleanup with proper peerHistory updates      │
└─────────────────────────────────────────────────────────┘
                          │
┌─────────────────────────────────────────────────────────┐
│              libp2p Stream Protocol                      │
│  Protocol ID: /mymonad/handshake/1.0.0                  │
│  Wire format: length-prefixed protobuf messages         │
└─────────────────────────────────────────────────────────┘
```

**Auto-discovery flow:**
1. DHT/mDNS discovers new peer
2. Session Manager checks: Have we handshaked before? Cooldown expired?
3. If eligible → auto-initiate handshake
4. Progress through stages automatically
5. At unmask stage → mark pending_approval, wait for human via CLI

**CLI override:** Manual initiation, listing, approval/rejection at any stage.

---

## 2. Wire Protocol

**Protocol ID:** `/mymonad/handshake/1.0.0`

**Message Format:** Length-prefixed protobuf

```
┌──────────────┬─────────────────────────────────┐
│ Length (4B)  │ Protobuf Message (N bytes)      │
│ big-endian   │                                 │
└──────────────┴─────────────────────────────────┘
```

**Protobuf Messages** (`api/proto/handshake.proto`):

```protobuf
message HandshakeEnvelope {
  MessageType type = 1;
  bytes payload = 2;
  int64 timestamp = 3;
  bytes signature = 4;
}

enum MessageType {
  ATTESTATION_REQUEST = 0;
  ATTESTATION_RESPONSE = 1;
  VECTOR_MATCH_REQUEST = 2;
  VECTOR_MATCH_RESPONSE = 3;
  DEALBREAKER_REQUEST = 4;
  DEALBREAKER_RESPONSE = 5;
  CHAT_MESSAGE = 6;
  UNMASK_REQUEST = 7;
  UNMASK_RESPONSE = 8;
  REJECT = 9;
}
```

**Stream Lifecycle:**
```
Initiator                         Responder
    │──── ATTESTATION_REQUEST ────────>│
    │<─── ATTESTATION_RESPONSE ────────│
    │──── VECTOR_MATCH_REQUEST ───────>│
    │<─── VECTOR_MATCH_RESPONSE ───────│
    │──── DEALBREAKER_REQUEST ────────>│
    │<─── DEALBREAKER_RESPONSE ────────│
    │<─────── CHAT_MESSAGE ───────────>│ (bidirectional)
    │──── UNMASK_REQUEST ─────────────>│
    │<─── UNMASK_RESPONSE ─────────────│
```

---

## 3. Session Manager

**Location:** `internal/handshake/manager.go`

```go
type Session struct {
    ID              string
    PeerID          peer.ID
    Role            protocol.Role
    Handshake       *protocol.Handshake
    Stream          network.Stream
    StartedAt       time.Time
    LastActivity    time.Time

    LocalMonad      []byte  // Zeroed on cleanup
    PeerMonad       []byte  // Zeroed on cleanup

    PendingApproval     bool
    PendingApprovalType string
    PendingAt           time.Time

    chatRelay       chan ChatMessage // Not stored, relayed directly
}

type Manager struct {
    mu               sync.RWMutex
    host             host.Host
    sessions         map[string]*Session
    peerHistory      map[peer.ID]time.Time

    autoInitiate     bool
    cooldownDuration time.Duration
    threshold        float32
}
```

**Critical:** `Session.Cleanup()` must zero all sensitive byte slices.

**Critical:** `removeSession()` must update `peerHistory` before deletion to prevent reconnection loops.

---

## 4. gRPC API Extensions

Add to `api/proto/monad.proto`:

```protobuf
service AgentService {
  // Existing RPCs...

  rpc StartHandshake(StartHandshakeRequest) returns (StartHandshakeResponse);
  rpc ListHandshakes(ListHandshakesRequest) returns (ListHandshakesResponse);
  rpc GetHandshake(GetHandshakeRequest) returns (GetHandshakeResponse);
  rpc ApproveHandshake(ApproveHandshakeRequest) returns (ApproveHandshakeResponse);
  rpc RejectHandshake(RejectHandshakeRequest) returns (RejectHandshakeResponse);
  rpc WatchHandshakes(WatchHandshakesRequest) returns (stream HandshakeEvent);
}

message HandshakeInfo {
  string session_id = 1;
  string peer_id = 2;
  string state = 3;
  string role = 4;
  int64 elapsed_seconds = 5;  // Server calculates, avoids NTP issues
  bool pending_approval = 6;
  string pending_approval_type = 7;
}
```

---

## 5. Human Notification (Pull Model)

**Agent daemon does NOT push notifications.** It exposes state via gRPC.

**CLI/mobile app is responsible for:**
1. Polling `WatchHandshakes` stream
2. Displaying local notifications (D-Bus, macOS, etc.)
3. Prompting user for approval

**No hard timeouts on pending approval.** Peer can send REJECT if they give up.

---

## 6. Architectural Gaps Addressed

### 6.1 Temporal Decay

```go
func (m *Monad) UpdateWithDecay(docEmbedding []float32, lambda float64) error {
    elapsed := time.Since(m.UpdatedAt).Hours() / 24
    decayFactor := float32(math.Exp(-lambda * elapsed))

    for i := range m.Vector {
        m.Vector[i] *= decayFactor
    }
    // ... continue with weighted update
}
```

Default λ = 0.01 (half-life ≈ 70 days).

### 6.2 Identity Recovery (BIP-39)

```go
func NewIdentityWithMnemonic() (*Identity, string, error) {
    entropy, _ := bip39.NewEntropy(256)
    mnemonic, _ := bip39.NewMnemonic(entropy)
    seed := bip39.NewSeed(mnemonic, "")
    privateKey := ed25519.NewKeyFromSeed(seed[:32])
    // ...
}
```

Display mnemonic on first run. User must write it down.

### 6.3 Source Weighting

```go
var DefaultWeights = []SourceWeight{
    {"*.eml", 3.0},
    {"*/personal/*", 2.5},
    {"*.md", 2.0},
    {".bash_history", 0.3},
    {"*", 1.0},
}
```

### 6.4 Metadata Sovereignty

**Documented limitation for v1.** DHT queries reveal interest areas. Mitigation (onion routing, mix networks) deferred to v2.

### 6.5 Unmasking Payload

```protobuf
message IdentityPayload {
    string display_name = 1;
    oneof contact {
        string email = 2;
        string signal_number = 3;
        string matrix_id = 4;
    }
    bytes pgp_public_key = 5;
    bytes contact_signature = 6;  // Proves same entity
}
```

### 6.6 State Machine Resilience

```go
func (m *Manager) removeSession(id string) {
    m.mu.Lock()
    defer m.mu.Unlock()

    if s, ok := m.sessions[id]; ok {
        m.peerHistory[s.PeerID] = time.Now()  // BEFORE delete
        s.Cleanup()
        delete(m.sessions, id)
    }
}
```

---

## 7. Error Handling

| Scenario | Action |
|----------|--------|
| Stream breaks mid-handshake | Mark failed, schedule cleanup after 5min |
| Duplicate handshake attempt | Reject if active session exists or cooldown not expired |
| Malformed protobuf | Log, reject, close stream |
| PoW spam | Hashcash + cooldown per peer |

---

## 8. Files to Create/Modify

**New files:**
- `api/proto/handshake.proto` - Wire format definitions
- `internal/handshake/manager.go` - Session manager
- `internal/handshake/stream.go` - libp2p stream handler
- `internal/handshake/codec.go` - Protobuf encoding/decoding
- `internal/crypto/mnemonic.go` - BIP-39 identity recovery
- `internal/embed/weights.go` - Source weighting

**Modified files:**
- `api/proto/monad.proto` - Add handshake RPCs
- `cmd/mymonad-agent/daemon.go` - Integrate handshake manager
- `cmd/mymonad-cli/commands.go` - Add handshake subcommands
- `pkg/monad/monad.go` - Add temporal decay
- `internal/embed/processor.go` - Add weighted processing

---

## 9. Testing Strategy

- Unit tests for each component
- Integration test: two agents complete full handshake
- Failure injection: stream drops, malformed messages, timeouts
- Race detection: concurrent handshakes with same peer

---

## 10. Security Checklist

- [ ] All sensitive bytes zeroed on cleanup
- [ ] Signatures verified before state transitions
- [ ] peerHistory updated on ALL session removals
- [ ] No plaintext monad transmission (only to MockTEE)
- [ ] Mnemonic displayed once, never stored

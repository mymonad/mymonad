# MyMonad Protocol v1.0 Design

## Overview

MyMonad is a decentralized P2P matchmaking protocol where autonomous agents negotiate human compatibility through privacy-preserving computation. Agents analyze local user data to build personality embeddings ("Monads"), then discover and evaluate potential matches via a distributed network without exposing raw personal data.

**First application:** MeetMyMonad (dating app built on the protocol).

## Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                           USER'S MACHINE                               │
│                                                                        │
│  ┌──────────────────────┐    IPC    ┌──────────────────────────────┐  │
│  │   Ingestion Daemon   │◀─────────▶│         P2P Agent            │  │
│  │                      │  (socket)  │                              │  │
│  │  • inotify watchers  │           │  • libp2p node               │  │
│  │  • deep extraction   │           │  • Kademlia DHT              │  │
│  │  • ONNX/llama.cpp    │           │  • 5-stage handshake         │  │
│  │  • OWNS monad.enc    │           │  • visibility state machine  │  │
│  └──────────────────────┘           └──────────────┬───────────────┘  │
│                                                    │                   │
└────────────────────────────────────────────────────┼───────────────────┘
                                                     │
                    ┌────────────────────────────────┼────────────────────┐
                    │              NETWORK           │                    │
                    │                                ▼                    │
                    │  ┌─────────┐    ┌─────────────────────────────┐    │
                    │  │ Peer B  │◀──▶│   TEE Relay Nodes           │    │
                    │  │ Agent   │    │   (neutral vector matching) │    │
                    │  └─────────┘    └─────────────────────────────┘    │
                    └─────────────────────────────────────────────────────┘
```

## v1.0 Scope

### Included

- P2P network (libp2p/Kademlia DHT)
- TEE-based vector matching (relay nodes + responder fallback)
- 5-stage handshake protocol
- Deep local data mining with inotify
- Local embedding generation (quantized transformers)
- Hashcash PoW spam prevention
- Configurable visibility modes (Active/Passive/Hidden)

### Deferred to v1.1+

- ZK-SNARKs for categorical attribute proofs
- LLM synthetic dialogue (Stage 4)
- Tokenomics/staking

## Component Design

### 1. Ingestion Daemon

Continuously builds and refines the Monad from local data. Runs as low-priority background service.

**Data sources (Deep Analysis):**

| Category | Sources |
|----------|---------|
| Communication | Email (mbox/Maildir), chat logs, terminal history |
| Documents | PDFs, Office docs, plain text, markdown |
| Browser | History URLs, bookmarks, cached content |
| Media | Music library metadata, video filenames, image EXIF |

**Architecture:**

```
┌────────────────────────────────────────────────────────────────┐
│                    Ingestion Daemon (Go)                       │
│                                                                │
│  ┌──────────────┐     ┌──────────────┐     ┌────────────────┐ │
│  │   Watchers   │────▶│   Extractors │────▶│   Embedding    │ │
│  │  (inotify)   │     │  (per-type)  │     │   Engine       │ │
│  │              │     │              │     │  (ONNX/llama)  │ │
│  └──────────────┘     └──────────────┘     └───────┬────────┘ │
│                                                    │          │
│  ┌──────────────┐                          ┌───────▼────────┐ │
│  │ Scheduler    │◀─────────────────────────│   Monad Store  │ │
│  │ (nice +19)   │                          │   (encrypted)  │ │
│  └──────────────┘                          └────────────────┘ │
└────────────────────────────────────────────────────────────────┘
```

**Key behaviors:**

- Runs at `nice +19` / `ionice -c3` (idle priority)
- Incremental updates via inotify (no full rescans)
- Monad stored encrypted at rest
- Configurable exclusion patterns

**Cache architecture (per-document embeddings):**

```
~/.mymonad/cache/
├── index.db              # File path → hash → embedding ID
├── embeddings/
│   ├── a1b2c3d4.vec      # Individual document embedding
│   ├── e5f6g7h8.vec
│   └── ...
└── checksums.db          # Integrity verification
```

Storing per-document embeddings enables fast Monad reconstruction from cache if `monad.enc` is corrupted.

### 2. P2P Agent

Participates in the DHT and executes the handshake protocol. Requests Monad from Ingestion Daemon via IPC.

**Identity:**

- DID format: `did:monad:<base58-pubkey>`
- Ed25519 keypair for signing
- X25519 derived keypair for encryption (birational map from Ed25519)

**LSH Discovery:**

```
Full Monad Vector (high-dimensional)
         │
         ▼
┌─────────────────────┐
│   LSH Projection    │  (random hyperplane hashing)
└──────────┬──────────┘
           │
           ▼
    LSH Signature (compact bitstring)
           │
           ▼
    Published to DHT (if Active/Passive mode)
```

**Visibility state machine:**

| Mode | DHT Behavior |
|------|--------------|
| ACTIVE | Queries DHT + publishes LSH hashes |
| PASSIVE | Publishes LSH hashes, listens only |
| HIDDEN | No DHT presence, agent offline to network |

### 3. IPC Layer

Ingestion Daemon owns `monad.enc`. P2P Agent requests current vector via IPC.

**Platform support:**

| Platform | Primary IPC | Fallback |
|----------|-------------|----------|
| Linux/macOS | Unix Domain Socket | gRPC over localhost TCP |
| Windows | Named Pipe | gRPC over localhost TCP |

**Protocol:**

```protobuf
service MonadStore {
  rpc GetMonad(GetMonadRequest) returns (EncryptedMonad);
  rpc WatchMonad(WatchRequest) returns (stream MonadUpdate);
  rpc Status(StatusRequest) returns (IngestionStatus);
}
```

### 4. Handshake Protocol

Five-stage state machine for establishing compatibility.

```
Stage 1          Stage 2         Stage 3          Stage 4         Stage 5
Attestation  →   Vector Match →  Deal-breakers →  Human Chat  →   Unmask
(PoW + sig)      (TEE: S≥τ?)     (3 questions)    (direct P2P)    (exchange IDs)
```

**Stage 1 - Attestation:**
- Exchange signed firmware/version proofs
- Verify peer is legitimate MyMonad agent
- Hashcash PoW attached by initiator

**Stage 2 - Vector Match:**
- Both agents submit encrypted Monads to TEE relay
- TEE computes cosine similarity S(A,B)
- Proceed if S(A,B) >= τ (user-configurable threshold)

**Stage 3 - Deal-breakers:**
- Exchange 3 pre-defined yes/no questions set by users
- All 3 must match to proceed

**Stage 4 - Human Chat (v1.0):**
- Agents notify humans of compatible match
- Humans converse directly via encrypted P2P channel
- (v1.1+: LLM synthetic dialogue)

**Stage 5 - Unmask:**
- Both humans approve → exchange real identities
- Handshake complete

### 5. TEE Relay Nodes

Neutral third-party nodes for vector matching.

```
Agent A                 TEE Relay                 Agent B
   │                        │                        │
   │  1. Encrypted Monad_A  │                        │
   │───────────────────────▶│                        │
   │                        │  2. Encrypted Monad_B  │
   │                        │◀───────────────────────│
   │            ┌───────────┴───────────┐            │
   │            │   SGX/Nitro Enclave   │            │
   │            │  - Decrypt vectors    │            │
   │            │  - Compute S(A,B)     │            │
   │            │  - Purge vectors      │            │
   │            └───────────┬───────────┘            │
   │   3. Score S(A,B)      │      3. Score S(A,B)   │
   │◀───────────────────────│───────────────────────▶│
```

**Requirements:**
- Must run attested TEE (Intel SGX or AWS Nitro)
- Publishes attestation report to DHT
- Stateless: vectors purged after computation

**Fallback:** Responder's enclave if no relay available (user-configurable).

## Deployment

### Primary: Headless Daemon (Self-Hosted)

```
systemd
├── mymonad-ingest.service   (nice +19, owns Monad)
└── mymonad-agent.service    (libp2p node)

~/.mymonad/
├── config.toml
├── identity/
│   ├── keypair.enc          # Ed25519, encrypted with passphrase
│   └── keypair.pub
├── monad.enc                # Encrypted affinity vector
└── cache/                   # Per-document embeddings
```

### Secondary: TEE Cloud Hosting

- Agent runs in AWS Nitro Enclave or Azure SGX VM
- User provisions enclave, uploads encrypted identity
- Attestation proves host cannot inspect memory

### Mobile Thin Client

- Push notifications
- Manual actions (approve/reject, deal-breakers, visibility toggle)
- Connects to agent via encrypted tunnel
- No Monad stored or computed on phone

## Tech Stack

| Component | Technology |
|-----------|------------|
| Core daemons | Go |
| Embedding engine | C++ via CGO (ONNX/llama.cpp) |
| P2P networking | go-libp2p |
| IPC/messaging | Protobuf + gRPC |
| TEE enclaves | C++ (Intel SGX SDK) |

## Binaries

```
mymonad-ingest   # Ingestion daemon
mymonad-agent    # P2P agent
mymonad-relay    # TEE relay node
mymonad-cli      # User control interface
```

## Cryptography

| Operation | Key Type |
|-----------|----------|
| DID proof / attestation | Ed25519 sign |
| Handshake message signing | Ed25519 sign |
| Monad encryption at rest | X25519 + symmetric (NaCl secretbox) |
| P2P encrypted channels | X25519 (libp2p Noise protocol) |
| TEE vector submission | X25519 box to relay's enclave key |

Single seed derives both Ed25519 (signing) and X25519 (encryption) keypairs.

## Security

**Threat mitigations:**

| Threat | Mitigation |
|--------|------------|
| Monad exfiltration | Encrypted at rest, only decrypted in TEE |
| Rogue relay node | Attestation verification before submission |
| Network snooping | libp2p TLS encryption |
| Spam/scraping | Hashcash PoW + attestation |
| Side-channel leaks | Agents in isolated cgroups |
| Correlation attacks | LSH reveals bucket only, not raw data |

**Zero persistence:**
- Handshake data in RAM only, purged on completion
- TEE relay purges vectors immediately after scoring

## Error Handling

| Scenario | Behavior |
|----------|----------|
| IPC timeout | Agent retries 3x, uses last-known Monad |
| Relay unreachable | Fallback to responder's enclave |
| Attestation failure | Reject handshake, log warning |
| Handshake timeout | State machine resets |
| Ingestion crash | Agent continues, ingestion restarts via systemd |
| Corrupted monad.enc | Rebuild from cached per-document embeddings |
| Corrupted cache entry | Rescan only that specific file |

## Testing

**Methodology:** TDD (Red → Green → Refactor)

**Coverage requirements:**

| Component | Minimum |
|-----------|---------|
| Ingestion extractors | 80% |
| Embedding engine | 80% |
| IPC protocol | 90% |
| Handshake state machine | 90% |
| P2P/DHT layer | 70% |

**Commands:**

```bash
make test              # All unit tests
make test-integration  # Integration tests
make test-enclave      # SGX simulation
make coverage          # Fails if <80%
```

## Build

```bash
make all       # Full build
make ingest    # Ingestion daemon
make agent     # P2P agent
make relay     # TEE relay node
make cli       # CLI tool
make enclave   # SGX enclave
make dev       # Build + run with mock TEE
```

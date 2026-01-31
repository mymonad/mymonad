# MyMonad

Decentralized P2P matchmaking protocol for autonomous agents. Agents negotiate human compatibility through cryptographic proofs without exposing raw personal data.

## Overview

MyMonad enables privacy-preserving compatibility matching between users via their AI agents. Each user's preferences are represented as a high-dimensional "Monad" embedding vector. Agents discover and evaluate potential matches using:

- **Locality Sensitive Hashing (LSH)** for O(log n) similarity-based peer discovery
- **5-stage handshake protocol** with progressive trust establishment
- **Ed25519/X25519 cryptography** for identity and secure key exchange
- **libp2p/Kademlia DHT** for decentralized networking

No raw user data ever leaves the local device. Only cryptographic proofs and similarity scores are exchanged.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Applications                            │
├─────────────────────────────────────────────────────────────────┤
│  mymonad-agent     │  mymonad-cli      │  mymonad-ingest        │
│  (P2P daemon)      │  (user interface) │  (data processing)     │
├─────────────────────────────────────────────────────────────────┤
│                         Protocol Layer                          │
│  Handshake FSM  │  Attestation  │  Vector Match  │  Messages    │
├─────────────────────────────────────────────────────────────────┤
│                         Core Libraries                          │
│  Monad (vectors)  │  LSH (hashing)  │  Hashcash (anti-spam)    │
├─────────────────────────────────────────────────────────────────┤
│                         Infrastructure                          │
│  Crypto (identity)  │  Agent (P2P)  │  IPC (local comms)       │
└─────────────────────────────────────────────────────────────────┘
```

### Handshake Protocol

The 5-stage handshake establishes trust progressively:

1. **Attestation** - Verify peer is a legitimate MyMonad agent (Hashcash PoW)
2. **Vector Match** - Compare embeddings against similarity threshold τ
3. **Deal Breakers** - Exchange yes/no compatibility questions
4. **Human Chat** - Optional direct encrypted conversation
5. **Unmask** - Mutual consent to reveal identities

Each stage must pass before proceeding. Failure at any point terminates the handshake.

## Installation

### Requirements

- Go 1.21+
- Make (optional)

### Build

```bash
# Build all binaries
make build

# Or build individually
go build -o bin/mymonad-agent ./cmd/mymonad-agent
go build -o bin/mymonad-cli ./cmd/mymonad-cli
go build -o bin/mymonad-ingest ./cmd/mymonad-ingest
```

## Usage

```bash
# Start the agent daemon
./bin/mymonad-agent

# Use CLI for interaction
./bin/mymonad-cli

# Process local data for Monad generation
./bin/mymonad-ingest
```

## Development

### Testing

```bash
# Run all tests with race detection
make test

# Generate coverage report
make test-coverage

# Run specific package tests
go test -v ./pkg/protocol/...
go test -v ./internal/crypto/...
```

### Project Structure

```
.
├── cmd/                    # Application entrypoints
│   ├── mymonad-agent/      # P2P daemon
│   ├── mymonad-cli/        # Command-line interface
│   └── mymonad-ingest/     # Data ingestion service
├── pkg/                    # Public libraries
│   ├── monad/              # Core Monad type (affinity vectors)
│   ├── protocol/           # Handshake state machine & messages
│   ├── lsh/                # Locality Sensitive Hashing
│   └── hashcash/           # Proof-of-work for anti-spam
├── internal/               # Private implementation
│   ├── agent/              # P2P networking (libp2p, DHT)
│   ├── crypto/             # Identity & key management
│   ├── ingest/             # File watching & processing
│   └── ipc/                # Local IPC server
├── api/proto/              # Protobuf definitions
└── tests/                  # Integration tests
```

### Key Packages

| Package | Description |
|---------|-------------|
| `pkg/monad` | Affinity vector with running average updates and cosine similarity |
| `pkg/protocol` | 5-stage handshake FSM with state transitions and message types |
| `pkg/lsh` | Random hyperplane LSH for privacy-preserving similarity search |
| `pkg/hashcash` | Proof-of-work challenge/response for spam prevention |
| `internal/crypto` | Ed25519 signing, X25519 key exchange, encrypted storage |
| `internal/agent` | libp2p host, Kademlia DHT, peer discovery |

## Security

### Cryptographic Primitives

- **Ed25519** for digital signatures and identity
- **X25519** for Diffie-Hellman key exchange (with low-order point detection)
- **Argon2id** for key derivation from passwords
- **AES-256-GCM** for authenticated encryption

### Privacy Guarantees

- Raw affinity vectors never transmitted
- LSH signatures reveal only coarse similarity
- Handshake can fail at any stage without data leakage
- Zero persistence: conversation data purged after handshake completion

## Contributing

1. Fork the repository
2. Create a feature branch from `main`
3. Write tests first (TDD approach required)
4. Ensure 80%+ test coverage
5. Run `make test` to verify all tests pass
6. Submit a pull request

### Code Style

- Follow standard Go conventions
- Keep functions small and focused
- Handle all errors explicitly
- Document exported types and functions

### Commit Messages

```
[Type][Scope] Short description

Types: Feat, Fix, Update, Refactor
Scope: Package or component affected
```

Example: `[Feat][Protocol] Add challenge expiration validation`

## License

MIT License - see [LICENSE](LICENSE) for details.

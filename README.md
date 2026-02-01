# MyMonad

Decentralized P2P matchmaking protocol for autonomous agents. Agents negotiate human compatibility through cryptographic proofs without exposing raw personal data.

## Quick Start

```bash
# 1. Install Ollama and pull the embedding model
ollama pull nomic-embed-text

# 2. Build all binaries
make build

# 3. Start the ingest daemon (watches for document changes)
./bin/mymonad-ingest --watch-dirs ~/Documents

# 4. In another terminal, start the agent daemon
./bin/mymonad-agent

# 5. Check status
./bin/mymonad-cli status
```

## Prerequisites

- **Go 1.21+** - For building the binaries
- **Ollama** - Local LLM inference server for embeddings
  - Install: https://ollama.ai
  - Required model: `nomic-embed-text` (768-dimensional embeddings)
- **Make** (optional) - For convenience build commands

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

### mymonad-ingest

The ingest daemon watches directories for document changes and builds your personal Monad (embedding vector) using Ollama.

```bash
# Basic usage - watch ~/Documents
./bin/mymonad-ingest --watch-dirs ~/Documents

# Watch multiple directories
./bin/mymonad-ingest --watch-dirs ~/Documents,~/Notes,~/Projects

# Use a configuration file
./bin/mymonad-ingest --config ~/.config/mymonad/ingest.toml

# Custom Ollama settings
./bin/mymonad-ingest --watch-dirs ~/Documents \
  --ollama-url http://localhost:11434 \
  --model nomic-embed-text

# Debug mode
./bin/mymonad-ingest --watch-dirs ~/Documents --log-level debug
```

**Supported file types:** `.txt`, `.md`

### mymonad-agent

The agent daemon runs the P2P network node and handles peer discovery and handshakes.

```bash
# Basic usage with mDNS discovery (local network)
./bin/mymonad-agent

# Specify a port (default: 4001)
./bin/mymonad-agent --port 4001

# Connect to bootstrap peers
./bin/mymonad-agent --bootstrap /ip4/192.168.1.100/tcp/4001/p2p/12D3KooW...

# Disable mDNS (for servers or restricted networks)
./bin/mymonad-agent --mdns=false

# Use a configuration file
./bin/mymonad-agent --config ~/.config/mymonad/agent.toml

# Debug mode
./bin/mymonad-agent --log-level debug
```

### mymonad-cli

The CLI provides commands to interact with the running daemons.

```bash
# Show status of both daemons
./bin/mymonad-cli status

# List connected peers
./bin/mymonad-cli peers

# Manually connect to a peer
./bin/mymonad-cli bootstrap /ip4/192.168.1.100/tcp/4001/p2p/12D3KooWAbCdEf...

# Show local identity (Peer ID and DID)
./bin/mymonad-cli identity
```

## Configuration

Configuration files are optional. If not provided, sensible defaults are used. Files should be placed in `~/.config/mymonad/`.

### ingest.toml

```toml
[watch]
directories = ["~/Documents", "~/Notes"]
extensions = [".txt", ".md"]
ignore_hidden = true

[ollama]
url = "http://localhost:11434"
model = "nomic-embed-text"
timeout_seconds = 30

[storage]
monad_path = "~/.local/share/mymonad/monad.bin"
```

### agent.toml

```toml
[network]
port = 4001
# external_ip = "203.0.113.50"  # Uncomment if behind NAT

[discovery]
dns_seeds = []  # DNSADDR records for bootstrap
bootstrap = []  # Static multiaddrs: ["/ip4/1.2.3.4/tcp/4001/p2p/12D3KooW..."]
mdns_enabled = true

[protocol]
similarity_threshold = 0.85  # Minimum cosine similarity for match (0.0-1.0)
challenge_difficulty = 16    # Hashcash proof-of-work bits

[storage]
identity_path = "~/.local/share/mymonad/identity.key"
peers_cache = "~/.local/share/mymonad/peers.json"
```

### Default Paths

| Path | Description |
|------|-------------|
| `~/.config/mymonad/` | Configuration files |
| `~/.local/share/mymonad/` | Data directory |
| `~/.local/share/mymonad/agent.sock` | Agent daemon IPC socket |
| `~/.local/share/mymonad/ingest.sock` | Ingest daemon IPC socket |
| `~/.local/share/mymonad/identity.key` | Encrypted Ed25519 identity |
| `~/.local/share/mymonad/monad.bin` | Serialized Monad vector |

## CLI Commands

| Command | Description |
|---------|-------------|
| `status` | Show status of agent and ingest daemons (connection state, peer count, documents indexed) |
| `peers` | List all connected peers with their addresses and connection state |
| `bootstrap <multiaddr>` | Manually connect to a peer at the given libp2p multiaddress |
| `identity` | Display local Peer ID, DID, and listen addresses |

## Troubleshooting

### Ollama not running

**Symptom:** Ingest daemon fails to start or logs embedding errors.

```
failed to get embedding: connection refused
```

**Solution:**
```bash
# Start Ollama
ollama serve

# Verify the model is available
ollama list
# Should show: nomic-embed-text

# If not, pull it
ollama pull nomic-embed-text
```

### Socket permission errors

**Symptom:** CLI cannot connect to daemons.

```
failed to connect to agent daemon: permission denied
```

**Solution:**
```bash
# Check socket permissions
ls -la ~/.local/share/mymonad/*.sock

# Remove stale sockets (if daemons crashed)
rm ~/.local/share/mymonad/agent.sock
rm ~/.local/share/mymonad/ingest.sock

# Restart daemons
./bin/mymonad-ingest --watch-dirs ~/Documents &
./bin/mymonad-agent &
```

### mDNS not working on Linux

**Symptom:** Cannot discover local peers despite being on the same network.

**Causes:**
- Avahi daemon not running
- Firewall blocking mDNS (UDP port 5353)
- Docker/container network isolation

**Solution:**
```bash
# Check if Avahi is running
systemctl status avahi-daemon

# Start if not running
sudo systemctl start avahi-daemon

# Allow mDNS through firewall (ufw)
sudo ufw allow 5353/udp

# For Docker, use host networking or manual bootstrap
./bin/mymonad-agent --mdns=false --bootstrap /ip4/HOST_IP/tcp/4001/p2p/PEER_ID
```

### Agent cannot bind to port

**Symptom:** Agent fails to start with port binding error.

```
failed to create host: listen tcp4 0.0.0.0:4001: bind: address already in use
```

**Solution:**
```bash
# Find what's using the port
lsof -i :4001

# Use a different port
./bin/mymonad-agent --port 4002

# Or use random port
./bin/mymonad-agent --port 0
```

### Identity file corrupted

**Symptom:** Agent fails to start with identity loading error.

```
failed to load/generate identity: failed to decrypt
```

**Solution:**
```bash
# Remove the corrupted identity (will generate new one)
rm ~/.local/share/mymonad/identity.key

# Restart agent
./bin/mymonad-agent
```

Note: This generates a new identity. Your Peer ID and DID will change.

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

# Application Binaries Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement the three application binaries (mymonad-ingest, mymonad-agent, mymonad-cli) with real functionality.

**Architecture:** Three daemons communicating via Unix socket IPC. Ingest watches files and generates embeddings via Ollama. Agent runs P2P networking with multi-source discovery. CLI provides user interface.

**Tech Stack:** Go, libp2p, Ollama API, gRPC IPC, TOML config

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           User's Machine                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────┐     Unix Socket      ┌──────────────────────────┐    │
│  │mymonad-ingest│◄────────────────────►│     mymonad-agent        │    │
│  │              │    (gRPC IPC)         │                          │    │
│  │ • Watches    │                       │ • P2P Host (libp2p)      │    │
│  │   ~/Documents│                       │ • DHT (Kademlia)         │    │
│  │ • Ollama     │                       │ • Handshake Protocol     │    │
│  │   embeddings │                       │ • Discovery (DNSADDR +   │    │
│  │ • Updates    │                       │   user peers + mDNS)     │    │
│  │   Monad      │                       │                          │    │
│  └──────────────┘                       └──────────▲───────────────┘    │
│                                                    │                    │
│  ┌──────────────┐     Unix Socket                  │                    │
│  │ mymonad-cli  │◄─────────────────────────────────┘                    │
│  │              │    (gRPC IPC)                                         │
│  │ • Status     │                                                       │
│  │ • Peer list  │                                                       │
│  │ • Manual     │                                                       │
│  │   bootstrap  │                                                       │
│  └──────────────┘                                                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ P2P (TCP/QUIC)
                                    ▼
                        ┌───────────────────────┐
                        │   MyMonad Network     │
                        │   (Other Agents)      │
                        └───────────────────────┘
```

## Binary Specifications

### mymonad-ingest

**Purpose:** Watch local files, generate embeddings, maintain Monad vector.

```
Config: ~/.config/mymonad/ingest.toml
Socket: ~/.local/share/mymonad/ingest.sock
Data:   ~/.local/share/mymonad/monad.bin (encrypted)

Flags:
  --config       Path to config file
  --watch-dirs   Directories to watch (default: ~/Documents)
  --ollama-url   Ollama API endpoint (default: http://localhost:11434)
  --model        Embedding model (default: nomic-embed-text)
```

### mymonad-agent

**Purpose:** P2P daemon - discovery, DHT, handshake protocol.

```
Config: ~/.config/mymonad/agent.toml
Socket: ~/.local/share/mymonad/agent.sock

Flags:
  --config         Path to config file
  --port           P2P listen port (default: 0 = random)
  --dns-seeds      DNSADDR seeds (default: _dnsaddr.bootstrap.mymonad.net)
  --bootstrap      Additional multiaddrs to bootstrap from
  --mdns           Enable mDNS discovery (default: false, dev only)
  --ingest-socket  Path to ingest daemon socket
```

### mymonad-cli

**Purpose:** User interface to query and control the agent.

```
Commands:
  mymonad-cli status           Show agent and ingest status
  mymonad-cli peers            List connected peers
  mymonad-cli bootstrap <addr> Manually connect to a peer
  mymonad-cli identity         Show local DID and peer ID
  mymonad-cli matches          Show pending/active handshakes
```

## Multi-Source Discovery

### DNSADDR Resolution

```
Query: _dnsaddr.bootstrap.mymonad.net TXT

Response:
  "dnsaddr=/dns4/node1.mymonad.net/tcp/4001/p2p/12D3Koo..."
  "dnsaddr=/dns4/node2.mymonad.net/tcp/4001/p2p/12D3Koo..."
```

### Discovery Priority

1. User-defined bootstrap (highest trust)
2. DNSADDR seeds (community trust)
3. DHT peer exchange (protocol trust)
4. mDNS if enabled (local only)

## Embedding Pipeline

```
File Event (create/modify)
         │
         ▼
┌─────────────────┐
│ Extension Check │ ← Only: .txt, .md
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Text Extraction │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Chunking        │ ← Split into ~512 token chunks
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Ollama Embed    │ ← nomic-embed-text (768 dimensions)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Average Chunks  │ ← Single vector per document
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Update Monad    │ ← Running average into Monad.Vector
└─────────────────┘
```

## Configuration

### Directory Structure

```
~/.config/mymonad/
├── ingest.toml
└── agent.toml

~/.local/share/mymonad/
├── identity.key         # Encrypted Ed25519 private key
├── monad.bin            # Encrypted Monad vector
├── peers.json           # Cached known peers
├── ingest.sock          # IPC socket (runtime)
└── agent.sock           # IPC socket (runtime)
```

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
port = 0
external_ip = ""

[discovery]
dns_seeds = ["_dnsaddr.bootstrap.mymonad.net"]
bootstrap = []
mdns_enabled = false

[protocol]
similarity_threshold = 0.7
challenge_difficulty = 20

[storage]
identity_path = "~/.local/share/mymonad/identity.key"
peers_cache = "~/.local/share/mymonad/peers.json"
```

## Error Handling

| Category | Handling | Example |
|----------|----------|---------|
| Fatal | Log + exit | Can't bind socket, invalid identity |
| Recoverable | Log + retry | Ollama timeout, peer disconnect |
| Ignorable | Debug log | Unsupported file type, empty file |

### Retry Strategy

- Ollama calls: 3 retries, exponential backoff (1s, 2s, 4s)
- Peer connections: 5 retries, exponential backoff (2s, 4s, 8s, 16s, 32s)
- DNS resolution: 2 retries, 5s timeout per seed

## Security

- Identity key encrypted with Argon2id + AES-256-GCM
- Monad encrypted with key derived from identity
- Sockets created with 0600 permissions
- No secrets in config files

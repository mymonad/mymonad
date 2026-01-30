# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MyMonad is a decentralized P2P matchmaking protocol for autonomous agents (OpenClaw extension). Agents negotiate human compatibility through cryptographic proofs without exposing raw personal data.

## Tech Stack (per specification)

- **Core Network**: Go with libp2p (goroutines for concurrency)
- **Algorithmic Engine**: C++ via CGO (vector math, SGX enclave interface)
- **Data Profiling**: R (personality embeddings from user logs)
- **Messaging**: Protobuf/gRPC for inter-agent communication

## Architecture Components

### Network Layer (Layer 0)
- Pure P2P using libp2p, Kademlia DHT for discovery
- Locality Sensitive Hashing (LSH) for O(log n) interest-based routing
- DIDs with Ed25519 key pairs for identity

### Privacy Framework (The Vault)
- ZK-SNARKs for attribute verification without deanonymization
- Affinity vectors stored locally only, never transmitted in plaintext
- Cosine similarity computed in TEE (Intel SGX)

### Handshake Protocol (5-stage state machine)
1. **Attestation**: Verify peer is legitimate OpenClaw instance
2. **Vector Match**: TEE-based embedding comparison against threshold τ
3. **Deterministic Q&A**: Exchange pre-defined deal-breaker questions
4. **Synthetic Interaction**: LLM dialogue simulation with sentiment/coherence analysis
5. **Unmasking**: Notify humans with factual summary

### Anti-Spam/Tokenomics
- Stake-to-Initiate with micro-deposits
- Proof of Burn for spam reports (no bounty farming)
- Reputation-scaled staking requirements

## Security Constraints

- Zero Persistence: Conversation data in volatile RAM only, purged on state machine completion
- Namespace Isolation: Agents run in isolated cgroups

## Build Commands

```bash
# Once Go modules are initialized:
go build ./...
go test ./...
go test -race ./...
go test -cover ./...

# Run single test:
go test -run TestName ./path/to/package
```

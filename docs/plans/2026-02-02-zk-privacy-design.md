# ZK Privacy Proofs Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable zero-knowledge verification of LSH similarity claims without revealing signatures, using gnark with PlonK backend for transparent universal setup.

**Architecture:** Optional ZK proof exchange between discovery and handshake, proving Hamming distance bound without trusted per-circuit setup.

**Tech Stack:** gnark (PlonK backend), MiMC hash (SNARK-friendly), Protocol Buffers (messages)

---

## 1. Overview

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        ZK Privacy Proof System                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │  Discovery   │───▶│   ZK Proof   │───▶│  Handshake   │              │
│  │   Manager    │    │   Exchange   │    │   Stage 1    │              │
│  └──────────────┘    └──────────────┘    └──────────────┘              │
│         │                   │                   │                       │
│         │ LSH Match         │ Prove/Verify      │ PoW Challenge         │
│         ▼                   ▼                   ▼                       │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │     DHT      │    │    gnark     │    │  Anti-Spam   │              │
│  │  (ZK flag)   │    │   (PlonK)    │    │   Service    │              │
│  └──────────────┘    └──────────────┘    └──────────────┘              │
│         │                   │                                           │
│         │ Capability        │ Circuit: Hamming ≤ k                      │
│         ▼                   ▼                                           │
│  ┌─────────────────────────────────────────────────────┐                │
│  │           /mymonad/zkproof/1.0.0 Protocol           │                │
│  └─────────────────────────────────────────────────────┘                │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| ZK System | gnark with PlonK | Pure Go, universal setup, no per-circuit ceremony |
| Proof Statement | Hamming distance ≤ k | Aligns with LSH, simpler circuit than cosine |
| Protocol Position | After discovery, before handshake | Optional upgrade, doesn't modify existing flows |
| Capability Discovery | DHT flag + local config | Advertise capability, user controls requirement |
| Trusted Setup | Hermez/Zcash Powers of Tau | Public ceremonies, reusable universal setup |

### Protocol Flow

```
    Alice                                      Bob
      │                                          │
      │◀─────── Discovery Match ────────────────▶│
      │         (LSH signatures exchanged)       │
      │                                          │
      │  [Check: Does Bob advertise ZK?]         │
      │  [Check: Does Alice require ZK?]         │
      │                                          │
      │  ──── ZKProofRequest ──────────────────▶ │
      │       {threshold_k, alice_commitment}    │
      │                                          │
      │  ◀─── ZKProofResponse ───────────────── │
      │       {proof, bob_commitment}            │
      │                                          │
      │  ──── ZKProofResponse ─────────────────▶ │
      │       {proof, alice_commitment}          │
      │                                          │
      │  [Both verify: Hamming(sigA, sigB) ≤ k]  │
      │                                          │
      │◀─────── Proceed to Handshake ──────────▶│
      │                                          │
```

---

## 2. Circuit Design

### Proof Statement

The ZK circuit proves:

> "I know a signature `S` such that `Commitment(S) = C` and `HammingDistance(S, S_peer) ≤ k`"

Where:
- `S` is the prover's LSH signature (private witness)
- `C` is the prover's public commitment (public input)
- `S_peer` is the peer's revealed signature (public input)
- `k` is the agreed threshold (public input)

### Circuit Definition (gnark)

```go
// pkg/zkproof/circuit.go

import (
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/std/hash/mimc"
)

const (
    SignatureBits = 256  // LSH signature length
)

// HammingCircuit proves Hamming distance bound without revealing signature
type HammingCircuit struct {
    // Private witness (prover's secret)
    Signature [SignatureBits]frontend.Variable `gnark:",secret"`

    // Public inputs
    Commitment      frontend.Variable   `gnark:",public"`  // Hash of prover's signature
    PeerSignature   [SignatureBits]frontend.Variable `gnark:",public"`
    MaxDistance     frontend.Variable   `gnark:",public"`  // Threshold k
}

func (c *HammingCircuit) Define(api frontend.API) error {
    // 1. Verify commitment matches signature
    if err := c.verifyCommitment(api); err != nil {
        return err
    }

    // 2. Compute Hamming distance
    distance := c.computeHammingDistance(api)

    // 3. Assert distance ≤ threshold
    api.AssertIsLessOrEqual(distance, c.MaxDistance)

    return nil
}
```

### Commitment Verification

```go
// verifyCommitment ensures the signature matches the public commitment
func (c *HammingCircuit) verifyCommitment(api frontend.API) error {
    // Pack signature bits into field elements for hashing
    packed := c.packSignature(api)

    // MiMC hash (SNARK-friendly)
    mimc, err := mimc.NewMiMC(api)
    if err != nil {
        return err
    }

    for _, p := range packed {
        mimc.Write(p)
    }

    computedCommitment := mimc.Sum()
    api.AssertIsEqual(computedCommitment, c.Commitment)

    return nil
}

func (c *HammingCircuit) packSignature(api frontend.API) []frontend.Variable {
    // Pack 256 bits into 4 x 64-bit field elements
    packed := make([]frontend.Variable, 4)

    for i := 0; i < 4; i++ {
        var acc frontend.Variable = 0
        for j := 0; j < 64; j++ {
            bitIdx := i*64 + j
            shifted := api.Mul(c.Signature[bitIdx], 1<<j)
            acc = api.Add(acc, shifted)
        }
        packed[i] = acc
    }

    return packed
}
```

### Hamming Distance Computation

```go
// computeHammingDistance counts differing bits between signatures
func (c *HammingCircuit) computeHammingDistance(api frontend.API) frontend.Variable {
    var distance frontend.Variable = 0

    for i := 0; i < SignatureBits; i++ {
        // XOR: different bits produce 1
        xor := api.Xor(c.Signature[i], c.PeerSignature[i])

        // Accumulate
        distance = api.Add(distance, xor)
    }

    return distance
}
```

### Circuit Compilation

```go
// pkg/zkproof/setup.go

import (
    "github.com/consensys/gnark-crypto/ecc"
    "github.com/consensys/gnark/backend/plonk"
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/frontend/cs/scs"
)

type CompiledCircuit struct {
    ConstraintSystem constraint.ConstraintSystem
    ProvingKey       plonk.ProvingKey
    VerifyingKey     plonk.VerifyingKey
}

// CompileCircuit compiles the Hamming circuit (done once at startup)
func CompileCircuit() (*CompiledCircuit, error) {
    var circuit HammingCircuit

    // Compile to constraint system
    cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
    if err != nil {
        return nil, fmt.Errorf("compile circuit: %w", err)
    }

    // Generate keys using universal setup (SRS)
    srs, err := loadUniversalSetup(cs.GetNbConstraints())
    if err != nil {
        return nil, fmt.Errorf("load SRS: %w", err)
    }

    pk, vk, err := plonk.Setup(cs, srs)
    if err != nil {
        return nil, fmt.Errorf("setup keys: %w", err)
    }

    return &CompiledCircuit{
        ConstraintSystem: cs,
        ProvingKey:       pk,
        VerifyingKey:     vk,
    }, nil
}
```

---

## 3. Proof Generation & Verification

### Prover Implementation

```go
// pkg/zkproof/prover.go

type Prover struct {
    compiled *CompiledCircuit
}

type ProofResult struct {
    Proof      []byte
    Commitment []byte
    PublicInputs PublicInputs
}

type PublicInputs struct {
    Commitment    []byte
    PeerSignature []byte
    MaxDistance   uint32
}

// GenerateProof creates a ZK proof of Hamming distance bound
func (p *Prover) GenerateProof(
    mySignature []byte,
    peerSignature []byte,
    maxDistance uint32,
) (*ProofResult, error) {
    // Compute commitment to our signature
    commitment := computeMiMCCommitment(mySignature)

    // Build witness
    witness, err := p.buildWitness(mySignature, peerSignature, commitment, maxDistance)
    if err != nil {
        return nil, fmt.Errorf("build witness: %w", err)
    }

    // Generate proof
    proof, err := plonk.Prove(p.compiled.ConstraintSystem, p.compiled.ProvingKey, witness)
    if err != nil {
        return nil, fmt.Errorf("generate proof: %w", err)
    }

    // Serialize proof
    var proofBuf bytes.Buffer
    if _, err := proof.WriteTo(&proofBuf); err != nil {
        return nil, fmt.Errorf("serialize proof: %w", err)
    }

    return &ProofResult{
        Proof:      proofBuf.Bytes(),
        Commitment: commitment,
        PublicInputs: PublicInputs{
            Commitment:    commitment,
            PeerSignature: peerSignature,
            MaxDistance:   maxDistance,
        },
    }, nil
}

func (p *Prover) buildWitness(
    signature, peerSignature, commitment []byte,
    maxDistance uint32,
) (witness.Witness, error) {
    var circuit HammingCircuit

    // Set private witness (signature bits)
    for i := 0; i < SignatureBits; i++ {
        byteIdx := i / 8
        bitIdx := i % 8
        bit := (signature[byteIdx] >> bitIdx) & 1
        circuit.Signature[i] = bit
    }

    // Set public inputs
    circuit.Commitment = new(big.Int).SetBytes(commitment)

    for i := 0; i < SignatureBits; i++ {
        byteIdx := i / 8
        bitIdx := i % 8
        bit := (peerSignature[byteIdx] >> bitIdx) & 1
        circuit.PeerSignature[i] = bit
    }

    circuit.MaxDistance = maxDistance

    return frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
}

func computeMiMCCommitment(signature []byte) []byte {
    // Pack into 4 x 64-bit values
    packed := make([]*big.Int, 4)
    for i := 0; i < 4; i++ {
        packed[i] = new(big.Int).SetBytes(signature[i*8 : (i+1)*8])
    }

    // MiMC hash
    h := mimc.NewMiMC()
    for _, p := range packed {
        h.Write(p.Bytes())
    }

    return h.Sum(nil)
}
```

### Verifier Implementation

```go
// pkg/zkproof/verifier.go

type Verifier struct {
    compiled *CompiledCircuit
}

// VerifyProof validates a ZK proof of Hamming distance bound
func (v *Verifier) VerifyProof(
    proofBytes []byte,
    proverCommitment []byte,
    mySignature []byte,
    maxDistance uint32,
) error {
    // Deserialize proof
    proof := plonk.NewProof(ecc.BN254)
    if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
        return fmt.Errorf("deserialize proof: %w", err)
    }

    // Build public witness (verifier knows these)
    publicWitness, err := v.buildPublicWitness(proverCommitment, mySignature, maxDistance)
    if err != nil {
        return fmt.Errorf("build public witness: %w", err)
    }

    // Verify
    if err := plonk.Verify(proof, v.compiled.VerifyingKey, publicWitness); err != nil {
        return fmt.Errorf("proof verification failed: %w", err)
    }

    return nil
}

func (v *Verifier) buildPublicWitness(
    commitment, peerSignature []byte,
    maxDistance uint32,
) (witness.Witness, error) {
    var circuit HammingCircuit

    // Only public inputs for verification
    circuit.Commitment = new(big.Int).SetBytes(commitment)

    for i := 0; i < SignatureBits; i++ {
        byteIdx := i / 8
        bitIdx := i % 8
        bit := (peerSignature[byteIdx] >> bitIdx) & 1
        circuit.PeerSignature[i] = bit
    }

    circuit.MaxDistance = maxDistance

    return frontend.NewWitness(&circuit, ecc.BN254.ScalarField(), frontend.PublicOnly())
}
```

### Proof Timing Expectations

| Operation | Expected Time | Notes |
|-----------|---------------|-------|
| Circuit compilation | ~2s | Once at startup |
| Proof generation | ~500ms | Per proof, depends on hardware |
| Proof verification | ~10ms | Fast verification |
| Proof size | ~1KB | PlonK proofs are compact |

---

## 4. Protocol Messages & Exchange

### Protocol Buffer Definitions

```protobuf
// api/proto/zkproof.proto

syntax = "proto3";
package mymonad.zkproof;

option go_package = "github.com/mymonad/mymonad/api/proto/zkproof";

// ZKProofRequest initiates a ZK proof exchange
message ZKProofRequest {
  uint32 max_distance = 1;     // Agreed Hamming threshold k
  bytes commitment = 2;        // Requester's MiMC commitment to their signature
  bytes signature = 3;         // Requester's revealed LSH signature (for peer to prove against)
}

// ZKProofResponse contains the proof
message ZKProofResponse {
  bytes proof = 1;             // Serialized PlonK proof
  bytes commitment = 2;        // Responder's MiMC commitment
  bytes signature = 3;         // Responder's revealed LSH signature
}

// ZKProofResult indicates verification outcome
message ZKProofResult {
  bool valid = 1;
  string error = 2;            // "invalid_proof", "commitment_mismatch", "threshold_exceeded"
}

// ZKCapability advertised in DHT bucket record
message ZKCapability {
  bool supported = 1;          // Peer supports ZK proofs
  string proof_system = 2;     // "plonk-bn254" for compatibility check
  uint32 max_signature_bits = 3;  // Supported signature length
}
```

### DHT Record Extension

```go
// internal/discovery/dht.go

type BucketRecord struct {
    PeerID       peer.ID      `json:"peer_id"`
    Addresses    []string     `json:"addrs"`
    Timestamp    int64        `json:"timestamp"`
    TTL          int64        `json:"ttl"`

    // ZK capability advertisement
    ZKCapability *ZKCapability `json:"zk_capability,omitempty"`
}

type ZKCapability struct {
    Supported        bool   `json:"supported"`
    ProofSystem      string `json:"proof_system"`       // "plonk-bn254"
    MaxSignatureBits uint32 `json:"max_signature_bits"` // 256
}

func (dm *DiscoveryManager) PublishToBucket(ctx context.Context) error {
    record := BucketRecord{
        PeerID:    dm.host.ID(),
        Addresses: multiaddrsToStrings(dm.host.Addrs()),
        Timestamp: time.Now().Unix(),
        TTL:       3600,
    }

    // Advertise ZK capability if enabled
    if dm.zkService != nil && dm.zkService.IsEnabled() {
        record.ZKCapability = &ZKCapability{
            Supported:        true,
            ProofSystem:      "plonk-bn254",
            MaxSignatureBits: 256,
        }
    }

    // ... publish to DHT
}
```

### Configuration

```go
// internal/zkproof/config.go

type ZKConfig struct {
    // Capability
    Enabled bool `toml:"enabled"`  // Advertise and accept ZK proofs

    // Requirement level
    RequireZK       bool `toml:"require_zk"`        // Reject peers without ZK
    PreferZK        bool `toml:"prefer_zk"`         // Prefer ZK peers, accept plaintext

    // Protocol settings
    ProofTimeout    time.Duration `toml:"proof_timeout"`     // Max time to wait for proof
    MaxDistance     uint32        `toml:"max_distance"`      // Default Hamming threshold

    // Performance
    ProverWorkers   int `toml:"prover_workers"`    // Parallel proof generation
}

func DefaultZKConfig() ZKConfig {
    return ZKConfig{
        Enabled:       false,  // Opt-in
        RequireZK:     false,
        PreferZK:      true,
        ProofTimeout:  30 * time.Second,
        MaxDistance:   64,     // 25% of 256 bits
        ProverWorkers: 2,
    }
}
```

### Exchange Flow Implementation

```go
// internal/zkproof/exchange.go

type ZKExchange struct {
    prover   *Prover
    verifier *Verifier
    config   ZKConfig
}

// InitiateExchange starts ZK proof exchange after discovery match
func (zk *ZKExchange) InitiateExchange(
    ctx context.Context,
    stream network.Stream,
    mySignature []byte,
    peerSignature []byte,
) error {
    // Generate our proof
    proofResult, err := zk.prover.GenerateProof(mySignature, peerSignature, zk.config.MaxDistance)
    if err != nil {
        return fmt.Errorf("generate proof: %w", err)
    }

    // Send request with our commitment and signature
    request := &ZKProofRequest{
        MaxDistance: zk.config.MaxDistance,
        Commitment:  proofResult.Commitment,
        Signature:   mySignature,
    }
    if err := writeMessage(stream, request); err != nil {
        return fmt.Errorf("send request: %w", err)
    }

    // Receive peer's response
    stream.SetReadDeadline(time.Now().Add(zk.config.ProofTimeout))
    var response ZKProofResponse
    if err := readMessage(stream, &response); err != nil {
        return fmt.Errorf("receive response: %w", err)
    }

    // Verify peer's proof against our signature
    if err := zk.verifier.VerifyProof(
        response.Proof,
        response.Commitment,
        mySignature,
        zk.config.MaxDistance,
    ); err != nil {
        sendResult(stream, &ZKProofResult{Valid: false, Error: err.Error()})
        return fmt.Errorf("peer proof invalid: %w", err)
    }

    // Send our proof
    myResponse := &ZKProofResponse{
        Proof:      proofResult.Proof,
        Commitment: proofResult.Commitment,
        Signature:  mySignature,
    }
    if err := writeMessage(stream, myResponse); err != nil {
        return fmt.Errorf("send response: %w", err)
    }

    // Receive verification result
    var result ZKProofResult
    if err := readMessage(stream, &result); err != nil {
        return fmt.Errorf("receive result: %w", err)
    }

    if !result.Valid {
        return fmt.Errorf("our proof rejected: %s", result.Error)
    }

    return nil
}

// HandleExchange responds to a ZK proof exchange request
func (zk *ZKExchange) HandleExchange(
    ctx context.Context,
    stream network.Stream,
    mySignature []byte,
) error {
    // Receive request
    stream.SetReadDeadline(time.Now().Add(zk.config.ProofTimeout))
    var request ZKProofRequest
    if err := readMessage(stream, &request); err != nil {
        return fmt.Errorf("receive request: %w", err)
    }

    // Generate our proof against peer's signature
    proofResult, err := zk.prover.GenerateProof(mySignature, request.Signature, request.MaxDistance)
    if err != nil {
        return fmt.Errorf("generate proof: %w", err)
    }

    // Send our response
    response := &ZKProofResponse{
        Proof:      proofResult.Proof,
        Commitment: proofResult.Commitment,
        Signature:  mySignature,
    }
    if err := writeMessage(stream, response); err != nil {
        return fmt.Errorf("send response: %w", err)
    }

    // Receive peer's proof
    var peerResponse ZKProofResponse
    if err := readMessage(stream, &peerResponse); err != nil {
        return fmt.Errorf("receive peer proof: %w", err)
    }

    // Verify peer's proof against our signature
    if err := zk.verifier.VerifyProof(
        peerResponse.Proof,
        request.Commitment,
        mySignature,
        request.MaxDistance,
    ); err != nil {
        sendResult(stream, &ZKProofResult{Valid: false, Error: err.Error()})
        return fmt.Errorf("peer proof invalid: %w", err)
    }

    // Send success
    sendResult(stream, &ZKProofResult{Valid: true})
    return nil
}
```

---

## 5. Integration & Error Handling

### ZK Service

```go
// internal/zkproof/service.go

type ZKService struct {
    mu       sync.RWMutex
    config   ZKConfig
    compiled *CompiledCircuit
    prover   *Prover
    verifier *Verifier

    // Metrics
    proofsGenerated uint64
    proofsVerified  uint64
    proofsFailed    uint64
}

func NewZKService(config ZKConfig) (*ZKService, error) {
    if !config.Enabled {
        return &ZKService{config: config}, nil
    }

    // Compile circuit at startup
    compiled, err := CompileCircuit()
    if err != nil {
        return nil, fmt.Errorf("compile circuit: %w", err)
    }

    return &ZKService{
        config:   config,
        compiled: compiled,
        prover:   &Prover{compiled: compiled},
        verifier: &Verifier{compiled: compiled},
    }, nil
}

func (zk *ZKService) IsEnabled() bool {
    return zk.config.Enabled && zk.compiled != nil
}

func (zk *ZKService) RequiresZK() bool {
    return zk.config.RequireZK
}

func (zk *ZKService) PrefersZK() bool {
    return zk.config.PreferZK
}
```

### Discovery Integration

```go
// internal/discovery/manager.go

// shouldRequireZK determines if ZK proof is needed for this peer
func (dm *DiscoveryManager) shouldRequireZK(peerRecord *BucketRecord) bool {
    // If we require ZK, peer must support it
    if dm.zkService.RequiresZK() {
        if peerRecord.ZKCapability == nil || !peerRecord.ZKCapability.Supported {
            slog.Debug("skipping peer: ZK required but not supported",
                "peer", peerRecord.PeerID,
            )
            return false  // Skip this peer entirely
        }
        return true
    }

    // If we prefer ZK and peer supports it, use it
    if dm.zkService.PrefersZK() {
        if peerRecord.ZKCapability != nil && peerRecord.ZKCapability.Supported {
            return true
        }
    }

    // Fall back to plaintext LSH
    return false
}

// postDiscoveryExchange handles the optional ZK step
func (dm *DiscoveryManager) postDiscoveryExchange(
    ctx context.Context,
    peer *DiscoveredPeer,
    peerRecord *BucketRecord,
) error {
    if !dm.shouldRequireZK(peerRecord) {
        // Proceed directly to handshake
        return dm.initiateHandshake(ctx, peer)
    }

    // Open ZK proof stream
    stream, err := dm.host.NewStream(ctx, peer.PeerID, "/mymonad/zkproof/1.0.0")
    if err != nil {
        return fmt.Errorf("open ZK stream: %w", err)
    }
    defer stream.Close()

    // Perform ZK exchange
    exchange := &ZKExchange{
        prover:   dm.zkService.prover,
        verifier: dm.zkService.verifier,
        config:   dm.zkService.config,
    }

    if err := exchange.InitiateExchange(ctx, stream, dm.localSignature, peer.Signature); err != nil {
        return fmt.Errorf("ZK exchange failed: %w", err)
    }

    slog.Info("ZK proof exchange successful", "peer", peer.PeerID)

    // Proceed to handshake
    return dm.initiateHandshake(ctx, peer)
}
```

### Error Types

```go
// internal/zkproof/errors.go

type ZKError string

const (
    ErrProofGenerationFailed ZKError = "proof_generation_failed"
    ErrProofVerificationFailed ZKError = "proof_verification_failed"
    ErrCommitmentMismatch    ZKError = "commitment_mismatch"
    ErrThresholdExceeded     ZKError = "threshold_exceeded"
    ErrIncompatibleSystem    ZKError = "incompatible_proof_system"
    ErrProofTimeout          ZKError = "proof_timeout"
    ErrCircuitNotReady       ZKError = "circuit_not_compiled"
)

func (e ZKError) Error() string {
    return string(e)
}
```

### Error Handling

```go
// internal/zkproof/exchange.go

func (zk *ZKExchange) handleError(stream network.Stream, err error, stage string) error {
    var zkErr ZKError

    switch {
    case errors.Is(err, context.DeadlineExceeded):
        zkErr = ErrProofTimeout
    case strings.Contains(err.Error(), "verification failed"):
        zkErr = ErrProofVerificationFailed
    case strings.Contains(err.Error(), "commitment"):
        zkErr = ErrCommitmentMismatch
    default:
        zkErr = ZKError(err.Error())
    }

    slog.Warn("ZK exchange error",
        "stage", stage,
        "error", zkErr,
        "peer", stream.Conn().RemotePeer(),
    )

    // Send error to peer
    sendResult(stream, &ZKProofResult{
        Valid: false,
        Error: string(zkErr),
    })

    return fmt.Errorf("%s: %w", stage, zkErr)
}
```

### Compatibility Checking

```go
// internal/zkproof/compat.go

const (
    SupportedProofSystem = "plonk-bn254"
    SupportedSignatureBits = 256
)

// CheckCompatibility verifies peer's ZK capability is compatible
func CheckCompatibility(peerCap *ZKCapability) error {
    if peerCap == nil {
        return fmt.Errorf("peer has no ZK capability")
    }

    if !peerCap.Supported {
        return fmt.Errorf("peer ZK not enabled")
    }

    if peerCap.ProofSystem != SupportedProofSystem {
        return fmt.Errorf("%w: peer uses %s, we use %s",
            ErrIncompatibleSystem,
            peerCap.ProofSystem,
            SupportedProofSystem,
        )
    }

    if peerCap.MaxSignatureBits != SupportedSignatureBits {
        return fmt.Errorf("signature length mismatch: peer=%d, local=%d",
            peerCap.MaxSignatureBits,
            SupportedSignatureBits,
        )
    }

    return nil
}
```

### Stream Handler Registration

```go
// internal/zkproof/handler.go

func (zk *ZKService) RegisterStreamHandler(host host.Host, dm *DiscoveryManager) {
    if !zk.IsEnabled() {
        return
    }

    host.SetStreamHandler("/mymonad/zkproof/1.0.0", func(stream network.Stream) {
        defer stream.Close()

        peerID := stream.Conn().RemotePeer()

        // Get our signature for this peer (from discovery)
        mySignature := dm.GetLocalSignature()

        exchange := &ZKExchange{
            prover:   zk.prover,
            verifier: zk.verifier,
            config:   zk.config,
        }

        if err := exchange.HandleExchange(context.Background(), stream, mySignature); err != nil {
            slog.Warn("ZK exchange handler failed",
                "peer", peerID,
                "error", err,
            )
            return
        }

        slog.Info("ZK exchange handled successfully", "peer", peerID)
    })
}
```

---

## 6. Testing Strategy

### Unit Tests: Circuit

```go
// pkg/zkproof/circuit_test.go

func TestHammingCircuit_ValidProof(t *testing.T) {
    // Two signatures with Hamming distance 20
    sigA := makeSignature(256)
    sigB := makeSimilarSignature(sigA, 20)

    commitment := computeMiMCCommitment(sigA)

    var circuit HammingCircuit
    setBits(circuit.Signature[:], sigA)
    setBits(circuit.PeerSignature[:], sigB)
    circuit.Commitment = new(big.Int).SetBytes(commitment)
    circuit.MaxDistance = 64  // Threshold

    assert := test.NewAssert(t)
    assert.ProverSucceeded(&circuit, &circuit, test.WithCurves(ecc.BN254))
}

func TestHammingCircuit_RejectsExceededThreshold(t *testing.T) {
    // Two signatures with Hamming distance 100
    sigA := makeSignature(256)
    sigB := makeSimilarSignature(sigA, 100)

    commitment := computeMiMCCommitment(sigA)

    var circuit HammingCircuit
    setBits(circuit.Signature[:], sigA)
    setBits(circuit.PeerSignature[:], sigB)
    circuit.Commitment = new(big.Int).SetBytes(commitment)
    circuit.MaxDistance = 64  // Threshold exceeded

    assert := test.NewAssert(t)
    assert.ProverFailed(&circuit, &circuit, test.WithCurves(ecc.BN254))
}

func TestHammingCircuit_RejectsWrongCommitment(t *testing.T) {
    sigA := makeSignature(256)
    sigB := makeSimilarSignature(sigA, 20)

    // Wrong commitment (different signature)
    wrongSig := makeSignature(256)
    wrongCommitment := computeMiMCCommitment(wrongSig)

    var circuit HammingCircuit
    setBits(circuit.Signature[:], sigA)
    setBits(circuit.PeerSignature[:], sigB)
    circuit.Commitment = new(big.Int).SetBytes(wrongCommitment)
    circuit.MaxDistance = 64

    assert := test.NewAssert(t)
    assert.ProverFailed(&circuit, &circuit, test.WithCurves(ecc.BN254))
}

func TestHammingCircuit_EdgeCaseExactThreshold(t *testing.T) {
    sigA := makeSignature(256)
    sigB := makeSimilarSignature(sigA, 64)  // Exactly at threshold

    commitment := computeMiMCCommitment(sigA)

    var circuit HammingCircuit
    setBits(circuit.Signature[:], sigA)
    setBits(circuit.PeerSignature[:], sigB)
    circuit.Commitment = new(big.Int).SetBytes(commitment)
    circuit.MaxDistance = 64

    assert := test.NewAssert(t)
    assert.ProverSucceeded(&circuit, &circuit, test.WithCurves(ecc.BN254))
}

func TestHammingCircuit_EdgeCaseOneOverThreshold(t *testing.T) {
    sigA := makeSignature(256)
    sigB := makeSimilarSignature(sigA, 65)  // One over threshold

    commitment := computeMiMCCommitment(sigA)

    var circuit HammingCircuit
    setBits(circuit.Signature[:], sigA)
    setBits(circuit.PeerSignature[:], sigB)
    circuit.Commitment = new(big.Int).SetBytes(commitment)
    circuit.MaxDistance = 64

    assert := test.NewAssert(t)
    assert.ProverFailed(&circuit, &circuit, test.WithCurves(ecc.BN254))
}
```

### Unit Tests: Prover & Verifier

```go
// pkg/zkproof/prover_test.go

func TestProver_GenerateValidProof(t *testing.T) {
    compiled, err := CompileCircuit()
    require.NoError(t, err)

    prover := &Prover{compiled: compiled}

    sigA := makeSignature(256)
    sigB := makeSimilarSignature(sigA, 20)

    result, err := prover.GenerateProof(sigA, sigB, 64)
    require.NoError(t, err)
    require.NotNil(t, result.Proof)
    require.NotNil(t, result.Commitment)
}

func TestProver_FailsOnThresholdExceeded(t *testing.T) {
    compiled, err := CompileCircuit()
    require.NoError(t, err)

    prover := &Prover{compiled: compiled}

    sigA := makeSignature(256)
    sigB := makeSimilarSignature(sigA, 100)  // Too different

    _, err = prover.GenerateProof(sigA, sigB, 64)
    require.Error(t, err)
}

func TestVerifier_AcceptsValidProof(t *testing.T) {
    compiled, err := CompileCircuit()
    require.NoError(t, err)

    prover := &Prover{compiled: compiled}
    verifier := &Verifier{compiled: compiled}

    sigA := makeSignature(256)
    sigB := makeSimilarSignature(sigA, 20)

    result, err := prover.GenerateProof(sigA, sigB, 64)
    require.NoError(t, err)

    err = verifier.VerifyProof(result.Proof, result.Commitment, sigB, 64)
    require.NoError(t, err)
}

func TestVerifier_RejectsTamperedProof(t *testing.T) {
    compiled, err := CompileCircuit()
    require.NoError(t, err)

    prover := &Prover{compiled: compiled}
    verifier := &Verifier{compiled: compiled}

    sigA := makeSignature(256)
    sigB := makeSimilarSignature(sigA, 20)

    result, err := prover.GenerateProof(sigA, sigB, 64)
    require.NoError(t, err)

    // Tamper with proof
    result.Proof[0] ^= 0xFF

    err = verifier.VerifyProof(result.Proof, result.Commitment, sigB, 64)
    require.Error(t, err)
}

func TestVerifier_RejectsWrongPeerSignature(t *testing.T) {
    compiled, err := CompileCircuit()
    require.NoError(t, err)

    prover := &Prover{compiled: compiled}
    verifier := &Verifier{compiled: compiled}

    sigA := makeSignature(256)
    sigB := makeSimilarSignature(sigA, 20)
    sigC := makeSignature(256)  // Different signature

    result, err := prover.GenerateProof(sigA, sigB, 64)
    require.NoError(t, err)

    // Verify against wrong signature
    err = verifier.VerifyProof(result.Proof, result.Commitment, sigC, 64)
    require.Error(t, err)
}
```

### Unit Tests: Configuration & Compatibility

```go
// internal/zkproof/config_test.go

func TestZKConfig_Defaults(t *testing.T) {
    cfg := DefaultZKConfig()

    require.False(t, cfg.Enabled)
    require.False(t, cfg.RequireZK)
    require.True(t, cfg.PreferZK)
    require.Equal(t, 30*time.Second, cfg.ProofTimeout)
    require.Equal(t, uint32(64), cfg.MaxDistance)
}

func TestCheckCompatibility_Compatible(t *testing.T) {
    cap := &ZKCapability{
        Supported:        true,
        ProofSystem:      "plonk-bn254",
        MaxSignatureBits: 256,
    }

    err := CheckCompatibility(cap)
    require.NoError(t, err)
}

func TestCheckCompatibility_WrongProofSystem(t *testing.T) {
    cap := &ZKCapability{
        Supported:        true,
        ProofSystem:      "groth16-bn254",
        MaxSignatureBits: 256,
    }

    err := CheckCompatibility(cap)
    require.ErrorIs(t, err, ErrIncompatibleSystem)
}

func TestCheckCompatibility_WrongSignatureBits(t *testing.T) {
    cap := &ZKCapability{
        Supported:        true,
        ProofSystem:      "plonk-bn254",
        MaxSignatureBits: 512,
    }

    err := CheckCompatibility(cap)
    require.Error(t, err)
    require.Contains(t, err.Error(), "signature length mismatch")
}

func TestCheckCompatibility_NotSupported(t *testing.T) {
    cap := &ZKCapability{
        Supported: false,
    }

    err := CheckCompatibility(cap)
    require.Error(t, err)
}

func TestCheckCompatibility_NilCapability(t *testing.T) {
    err := CheckCompatibility(nil)
    require.Error(t, err)
}
```

### Unit Tests: Service

```go
// internal/zkproof/service_test.go

func TestZKService_DisabledByDefault(t *testing.T) {
    cfg := DefaultZKConfig()
    svc, err := NewZKService(cfg)
    require.NoError(t, err)

    require.False(t, svc.IsEnabled())
}

func TestZKService_EnabledCompiles(t *testing.T) {
    cfg := DefaultZKConfig()
    cfg.Enabled = true

    svc, err := NewZKService(cfg)
    require.NoError(t, err)

    require.True(t, svc.IsEnabled())
    require.NotNil(t, svc.compiled)
}

func TestZKService_RequiresZK(t *testing.T) {
    cfg := DefaultZKConfig()
    cfg.Enabled = true
    cfg.RequireZK = true

    svc, err := NewZKService(cfg)
    require.NoError(t, err)

    require.True(t, svc.RequiresZK())
}
```

### Integration Tests

```go
// tests/zkproof_integration_test.go

func TestZKProof_FullExchange(t *testing.T) {
    // Setup two ZK-enabled services
    aliceCfg := DefaultZKConfig()
    aliceCfg.Enabled = true
    alice, err := NewZKService(aliceCfg)
    require.NoError(t, err)

    bobCfg := DefaultZKConfig()
    bobCfg.Enabled = true
    bob, err := NewZKService(bobCfg)
    require.NoError(t, err)

    // Create similar signatures
    aliceSig := makeSignature(256)
    bobSig := makeSimilarSignature(aliceSig, 20)

    // Alice generates proof
    aliceProof, err := alice.prover.GenerateProof(aliceSig, bobSig, 64)
    require.NoError(t, err)

    // Bob verifies Alice's proof
    err = bob.verifier.VerifyProof(aliceProof.Proof, aliceProof.Commitment, bobSig, 64)
    require.NoError(t, err)

    // Bob generates proof
    bobProof, err := bob.prover.GenerateProof(bobSig, aliceSig, 64)
    require.NoError(t, err)

    // Alice verifies Bob's proof
    err = alice.verifier.VerifyProof(bobProof.Proof, bobProof.Commitment, aliceSig, 64)
    require.NoError(t, err)
}

func TestZKProof_RejectsDissimilarPeers(t *testing.T) {
    cfg := DefaultZKConfig()
    cfg.Enabled = true
    svc, err := NewZKService(cfg)
    require.NoError(t, err)

    // Create very different signatures
    sigA := makeSignature(256)
    sigB := makeSimilarSignature(sigA, 150)  // 150 bits different

    // Proof generation should fail
    _, err = svc.prover.GenerateProof(sigA, sigB, 64)
    require.Error(t, err)
}

func TestZKProof_StreamExchange(t *testing.T) {
    // Setup two hosts with ZK capability
    alice, bob := setupZKEnabledPair(t)

    // Open ZK stream from Alice to Bob
    stream, err := alice.host.NewStream(context.Background(), bob.host.ID(), "/mymonad/zkproof/1.0.0")
    require.NoError(t, err)
    defer stream.Close()

    // Run exchange in goroutines
    var wg sync.WaitGroup
    var aliceErr, bobErr error

    wg.Add(2)
    go func() {
        defer wg.Done()
        exchange := &ZKExchange{prover: alice.zkService.prover, verifier: alice.zkService.verifier, config: alice.zkService.config}
        aliceErr = exchange.InitiateExchange(context.Background(), stream, alice.signature, bob.signature)
    }()

    go func() {
        defer wg.Done()
        // Bob accepts stream in handler
    }()

    wg.Wait()

    require.NoError(t, aliceErr)
    require.NoError(t, bobErr)
}
```

### Test Coverage Targets

| Component | Target | Focus Areas |
|-----------|--------|-------------|
| `circuit.go` | 95% | Constraint satisfaction, edge cases |
| `prover.go` | 90% | Proof generation, witness building |
| `verifier.go` | 90% | All verification paths |
| `service.go` | 85% | Lifecycle, configuration |
| `exchange.go` | 85% | Protocol flow, error handling |
| `compat.go` | 90% | All compatibility checks |
| Integration | N/A | Full exchange, stream handling |

---

## 7. Implementation Tasks

### Task 1: Circuit Definition

**Files:**
- Create: `pkg/zkproof/circuit.go`
- Create: `pkg/zkproof/circuit_test.go`

**Steps:**
1. Define HammingCircuit struct with gnark tags
2. Write failing circuit tests (valid, threshold exceeded, wrong commitment)
3. Implement Define() with commitment verification
4. Implement computeHammingDistance
5. Write edge case tests (exact threshold, one over)
6. Commit

### Task 2: Circuit Compilation & Setup

**Files:**
- Create: `pkg/zkproof/setup.go`
- Create: `pkg/zkproof/setup_test.go`

**Steps:**
1. Write failing test for CompileCircuit
2. Implement circuit compilation with PlonK
3. Implement loadUniversalSetup (embed or fetch SRS)
4. Write test for key generation
5. Commit

### Task 3: Prover Implementation

**Files:**
- Create: `pkg/zkproof/prover.go`
- Create: `pkg/zkproof/prover_test.go`

**Steps:**
1. Write failing tests for GenerateProof
2. Implement computeMiMCCommitment
3. Implement buildWitness
4. Implement proof generation and serialization
5. Write tests for threshold exceeded
6. Commit

### Task 4: Verifier Implementation

**Files:**
- Create: `pkg/zkproof/verifier.go`
- Create: `pkg/zkproof/verifier_test.go`

**Steps:**
1. Write failing tests for VerifyProof
2. Implement proof deserialization
3. Implement buildPublicWitness
4. Implement verification
5. Write tests for tampering, wrong signature
6. Commit

### Task 5: Protocol Buffer Definitions

**Files:**
- Create: `api/proto/zkproof.proto`

**Steps:**
1. Write protobuf definitions for ZKProofRequest, ZKProofResponse, ZKProofResult, ZKCapability
2. Run `make proto` to generate Go code
3. Commit

### Task 6: ZK Service

**Files:**
- Create: `internal/zkproof/service.go`
- Create: `internal/zkproof/service_test.go`

**Steps:**
1. Define ZKService struct and ZKConfig
2. Write failing tests for NewZKService
3. Implement service creation with circuit compilation
4. Implement IsEnabled, RequiresZK, PrefersZK
5. Commit

### Task 7: Exchange Protocol

**Files:**
- Create: `internal/zkproof/exchange.go`
- Create: `internal/zkproof/exchange_test.go`

**Steps:**
1. Define ZKExchange struct
2. Write failing tests for InitiateExchange
3. Implement initiator flow
4. Write failing tests for HandleExchange
5. Implement responder flow
6. Commit

### Task 8: Compatibility & Errors

**Files:**
- Create: `internal/zkproof/compat.go`
- Create: `internal/zkproof/errors.go`
- Create: `internal/zkproof/compat_test.go`

**Steps:**
1. Define ZKError constants
2. Write failing tests for CheckCompatibility
3. Implement compatibility checking
4. Write tests for all error cases
5. Commit

### Task 9: DHT Integration

**Files:**
- Modify: `internal/discovery/dht.go`
- Modify: `internal/discovery/manager.go`

**Steps:**
1. Extend BucketRecord with ZKCapability
2. Implement shouldRequireZK logic
3. Implement postDiscoveryExchange
4. Wire ZK service into discovery manager
5. Commit

### Task 10: Stream Handler

**Files:**
- Create: `internal/zkproof/handler.go`

**Steps:**
1. Implement RegisterStreamHandler
2. Wire into agent initialization
3. Commit

### Task 11: Agent Integration

**Files:**
- Modify: `cmd/mymonad-agent/daemon.go`
- Add: config parsing for ZK settings

**Steps:**
1. Add ZK config to agent.toml
2. Initialize ZKService in daemon
3. Register stream handler
4. Wire to discovery manager
5. Commit

### Task 12: Integration Tests

**Files:**
- Create: `tests/zkproof_integration_test.go`

**Steps:**
1. Write full exchange test (two services)
2. Write rejection test (dissimilar peers)
3. Write stream exchange test
4. Write compatibility negotiation test
5. Commit

---

## 8. Security Considerations

### Cryptographic Guarantees

| Property | Mechanism |
|----------|-----------|
| Zero-knowledge | PlonK proof reveals nothing about signature |
| Soundness | Computationally infeasible to forge proof |
| Commitment binding | MiMC hash binds prover to their signature |
| Universal setup | No per-circuit trusted ceremony |

### Trust Assumptions

| Component | Trust Level | Mitigation |
|-----------|-------------|------------|
| PlonK SRS | Public ceremony | Use Hermez/Zcash transcripts |
| gnark library | Audited | Track CVEs, update promptly |
| MiMC hash | SNARK-friendly | Well-studied, no known attacks |
| BN254 curve | 128-bit security | Sufficient for current threats |

### Attack Mitigations

| Attack | Defense |
|--------|---------|
| Proof forgery | PlonK soundness (computationally hard) |
| Commitment manipulation | MiMC preimage resistance |
| Replay proof | Proofs are peer-pair specific |
| Downgrade attack | RequireZK config rejects plaintext |
| Timing side-channel | Constant-time operations in gnark |

---

## 9. Configuration Reference

### agent.toml

```toml
[zk]
# Enable ZK proof capability
enabled = false

# Require peers to support ZK (reject plaintext LSH)
require_zk = false

# Prefer ZK when peer supports it
prefer_zk = true

# Maximum time to wait for proof generation/verification
proof_timeout = "30s"

# Default Hamming distance threshold (bits)
max_distance = 64

# Parallel proof generation workers
prover_workers = 2
```

### Privacy Levels

| Level | Config | Behavior |
|-------|--------|----------|
| Maximum | `require_zk = true` | Only connect to ZK-capable peers |
| Preferred | `prefer_zk = true` | Use ZK when available, fallback to plaintext |
| Disabled | `enabled = false` | No ZK capability advertised or used |

---

## 10. Future Enhancements

1. **STARK Migration**: When pure Go STARK libraries mature, migrate from PlonK for quantum resistance
2. **Proof Caching**: Cache proofs for repeated peer interactions within TTL
3. **Batch Verification**: Verify multiple proofs efficiently when many peers discovered
4. **Circuit Optimization**: Profile and optimize constraint count for faster proving
5. **Hardware Acceleration**: GPU proving for high-throughput nodes

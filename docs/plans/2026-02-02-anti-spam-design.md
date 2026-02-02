# Anti-Spam (Hashcash PoW) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement load-adaptive proof-of-work for Stage 1 (Attestation) to prevent spam and DoS attacks without requiring a reputation system.

**Architecture:** Tiered difficulty controller with sliding window metrics, server-issued nonces for freshness, and difficulty-scaled expiration windows.

**Tech Stack:** SHA-256 (proof-of-work), Protocol Buffers (messages), sliding window metrics

---

## 1. Overview

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Anti-Spam System                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │  Handshake   │───▶│   PoW        │───▶│  Difficulty  │              │
│  │  Stage 1     │    │  Verifier    │    │  Controller  │              │
│  └──────────────┘    └──────────────┘    └──────────────┘              │
│         │                   │                   │                       │
│         │ Challenge         │ Verify            │ Current Tier          │
│         ▼                   ▼                   ▼                       │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │   Nonce      │    │   Hashcash   │    │   Metrics    │              │
│  │   Store      │    │   (SHA-256)  │    │   Collector  │              │
│  │  (in-memory) │    └──────────────┘    └──────────────┘              │
│  └──────────────┘                               │                       │
│         │                                       │                       │
│         │ TTL eviction                          │ rate, failures        │
│         ▼                                       ▼                       │
│  ┌─────────────────────────────────────────────────┐                    │
│  │              Sliding Window (1 min)              │                    │
│  └─────────────────────────────────────────────────┘                    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Difficulty scaling | Load-adaptive | Self-regulating without reputation dependency |
| Load metrics | Rate + failure ratio | Distinguishes attacks from legitimate bursts |
| Scaling curve | Tiered (16→20→24→28) | Predictable, prevents oscillation |
| Cooldown | 5 minutes per tier | Anti-jitter, maintains defense during pulse attacks |
| Challenge freshness | Timestamp + server nonce | Prevents pre-computation |
| Expiration | Difficulty-scaled (30s base + 30s/tier) | Accounts for exponential PoW time |

### Difficulty Tiers

| Tier | Bits | Trigger | Expiration | Approx. Time |
|------|------|---------|------------|--------------|
| Normal | 16 | Default | 30s | ~1ms |
| Elevated | 20 | >10 req/min OR >10% failure | 60s | ~16ms |
| High | 24 | >50 req/min OR >30% failure | 90s | ~250ms |
| Critical | 28 | >100 req/min OR >50% failure | 120s | ~4s |

---

## 2. Challenge Protocol

### Protocol Buffer Definitions

```protobuf
// api/proto/pow.proto

syntax = "proto3";
package mymonad.pow;

option go_package = "github.com/mymonad/mymonad/api/proto/pow";

// PoWChallenge is sent by the verifier to the prover
message PoWChallenge {
  bytes nonce = 1;          // 16 bytes, random server nonce
  int64 timestamp = 2;      // Unix milliseconds, challenge creation time
  uint32 difficulty = 3;    // Required leading zero bits (16, 20, 24, 28)
  bytes peer_id = 4;        // Verifier's peer ID (binds challenge to session)
}

// PoWSolution is sent by the prover in response
message PoWSolution {
  bytes challenge_nonce = 1;  // Echo of challenge nonce
  int64 challenge_timestamp = 2;  // Echo of challenge timestamp
  uint64 counter = 3;         // PoW counter that produces valid hash
  bytes proof = 4;            // SHA-256(nonce || timestamp || peer_id || counter)
}

// PoWResult indicates verification outcome
message PoWResult {
  bool valid = 1;
  string error = 2;           // "expired", "invalid_nonce", "insufficient_difficulty", "hash_mismatch"
}
```

### Challenge-Response Flow

```
    Prover (Initiator)                    Verifier (Responder)
           │                                       │
           │  ──── Handshake Request ────────────▶ │
           │                                       │
           │                          [Generate nonce, check difficulty tier]
           │                                       │
           │  ◀─── PoWChallenge ────────────────── │
           │       {nonce, timestamp, difficulty}  │
           │                                       │
           │  [Mine: find counter where            │
           │   SHA-256(nonce||ts||peer||counter)   │
           │   has `difficulty` leading zeros]     │
           │                                       │
           │  ──── PoWSolution ──────────────────▶ │
           │       {nonce, timestamp, counter}     │
           │                                       │
           │                          [Verify: check expiration, nonce exists,
           │                           recompute hash, validate difficulty]
           │                                       │
           │  ◀─── PoWResult ─────────────────────│
           │       {valid: true}                   │
           │                                       │
           │  [Proceed to Stage 2]                 │
           │                                       │
```

### Mining Implementation

```go
// pkg/hashcash/miner.go

type Miner struct {
    maxIterations uint64  // Give up after this many attempts
}

type MineResult struct {
    Counter uint64
    Proof   []byte
    Elapsed time.Duration
}

// Mine finds a counter that produces a hash with required leading zeros
func (m *Miner) Mine(challenge *PoWChallenge, localPeerID []byte) (*MineResult, error) {
    start := time.Now()

    prefix := buildPrefix(challenge.Nonce, challenge.Timestamp, localPeerID)
    target := difficultyTarget(challenge.Difficulty)

    counterBuf := make([]byte, 8)

    for counter := uint64(0); counter < m.maxIterations; counter++ {
        binary.BigEndian.PutUint64(counterBuf, counter)

        hash := sha256.Sum256(append(prefix, counterBuf...))

        if meetsTarget(hash[:], target) {
            return &MineResult{
                Counter: counter,
                Proof:   hash[:],
                Elapsed: time.Since(start),
            }, nil
        }
    }

    return nil, fmt.Errorf("exceeded max iterations: %d", m.maxIterations)
}

func buildPrefix(nonce []byte, timestamp int64, peerID []byte) []byte {
    buf := make([]byte, len(nonce)+8+len(peerID))
    copy(buf, nonce)
    binary.BigEndian.PutUint64(buf[len(nonce):], uint64(timestamp))
    copy(buf[len(nonce)+8:], peerID)
    return buf
}

func difficultyTarget(bits uint32) []byte {
    // Target has `bits` leading zeros
    target := make([]byte, 32)
    byteIndex := bits / 8
    bitOffset := bits % 8
    if byteIndex < 32 {
        target[byteIndex] = 0x80 >> bitOffset
    }
    return target
}

func meetsTarget(hash, target []byte) bool {
    return bytes.Compare(hash, target) < 0
}
```

### Verification Implementation

```go
// pkg/hashcash/verifier.go

func Verify(challenge *PoWChallenge, solution *PoWSolution, proverPeerID []byte) error {
    // Check nonce matches
    if !bytes.Equal(challenge.Nonce, solution.ChallengeNonce) {
        return fmt.Errorf("nonce mismatch")
    }

    // Check timestamp matches
    if challenge.Timestamp != solution.ChallengeTimestamp {
        return fmt.Errorf("timestamp mismatch")
    }

    // Recompute hash
    prefix := buildPrefix(challenge.Nonce, challenge.Timestamp, proverPeerID)
    counterBuf := make([]byte, 8)
    binary.BigEndian.PutUint64(counterBuf, solution.Counter)

    hash := sha256.Sum256(append(prefix, counterBuf...))

    // Verify proof matches
    if !bytes.Equal(hash[:], solution.Proof) {
        return fmt.Errorf("hash mismatch")
    }

    // Verify difficulty
    target := difficultyTarget(challenge.Difficulty)
    if !meetsTarget(hash[:], target) {
        return fmt.Errorf("insufficient difficulty")
    }

    return nil
}
```

---

## 3. Difficulty Controller

### Core Structures

```go
// internal/antispam/controller.go

type DifficultyTier uint8

const (
    TierNormal   DifficultyTier = iota  // 16 bits
    TierElevated                         // 20 bits
    TierHigh                             // 24 bits
    TierCritical                         // 28 bits
)

func (t DifficultyTier) Bits() uint32 {
    return []uint32{16, 20, 24, 28}[t]
}

func (t DifficultyTier) Expiration() time.Duration {
    return []time.Duration{
        30 * time.Second,
        60 * time.Second,
        90 * time.Second,
        120 * time.Second,
    }[t]
}

type DifficultyController struct {
    mu              sync.RWMutex
    currentTier     DifficultyTier
    tierEnteredAt   time.Time

    // Sliding window metrics
    windowDuration  time.Duration
    challenges      []challengeRecord

    // Thresholds
    config          DifficultyConfig
}

type DifficultyConfig struct {
    WindowDuration     time.Duration  // Default: 1 minute
    CooldownDuration   time.Duration  // Default: 5 minutes

    // Tier escalation thresholds
    ElevatedRateThreshold   int     // Default: 10 req/min
    ElevatedFailureRate     float64 // Default: 0.10

    HighRateThreshold       int     // Default: 50 req/min
    HighFailureRate         float64 // Default: 0.30

    CriticalRateThreshold   int     // Default: 100 req/min
    CriticalFailureRate     float64 // Default: 0.50
}

type challengeRecord struct {
    timestamp time.Time
    succeeded bool
}
```

### Metrics Collection

```go
// internal/antispam/metrics.go

// RecordChallenge adds a challenge outcome to the sliding window
func (dc *DifficultyController) RecordChallenge(succeeded bool) {
    dc.mu.Lock()
    defer dc.mu.Unlock()

    now := time.Now()

    // Add new record
    dc.challenges = append(dc.challenges, challengeRecord{
        timestamp: now,
        succeeded: succeeded,
    })

    // Evict records outside window
    dc.evictStale(now)

    // Recalculate tier
    dc.recalculateTier(now)
}

func (dc *DifficultyController) evictStale(now time.Time) {
    cutoff := now.Add(-dc.windowDuration)

    firstValid := 0
    for i, r := range dc.challenges {
        if r.timestamp.After(cutoff) {
            firstValid = i
            break
        }
        firstValid = i + 1
    }

    dc.challenges = dc.challenges[firstValid:]
}

func (dc *DifficultyController) getMetrics() (rate int, failureRate float64) {
    total := len(dc.challenges)
    if total == 0 {
        return 0, 0.0
    }

    failures := 0
    for _, r := range dc.challenges {
        if !r.succeeded {
            failures++
        }
    }

    return total, float64(failures) / float64(total)
}
```

### Tier Calculation

```go
// internal/antispam/tier.go

func (dc *DifficultyController) recalculateTier(now time.Time) {
    rate, failureRate := dc.getMetrics()

    // Determine target tier based on metrics
    targetTier := dc.calculateTargetTier(rate, failureRate)

    // Escalation: immediate
    if targetTier > dc.currentTier {
        dc.currentTier = targetTier
        dc.tierEnteredAt = now
        slog.Info("difficulty escalated",
            "tier", dc.currentTier,
            "bits", dc.currentTier.Bits(),
            "rate", rate,
            "failure_rate", failureRate,
        )
        return
    }

    // De-escalation: requires cooldown
    if targetTier < dc.currentTier {
        if now.Sub(dc.tierEnteredAt) >= dc.config.CooldownDuration {
            // Decay one tier at a time
            dc.currentTier--
            dc.tierEnteredAt = now
            slog.Info("difficulty de-escalated",
                "tier", dc.currentTier,
                "bits", dc.currentTier.Bits(),
                "rate", rate,
                "failure_rate", failureRate,
            )
        }
    }
}

func (dc *DifficultyController) calculateTargetTier(rate int, failureRate float64) DifficultyTier {
    cfg := dc.config

    // Check from highest to lowest
    if rate > cfg.CriticalRateThreshold || failureRate > cfg.CriticalFailureRate {
        return TierCritical
    }
    if rate > cfg.HighRateThreshold || failureRate > cfg.HighFailureRate {
        return TierHigh
    }
    if rate > cfg.ElevatedRateThreshold || failureRate > cfg.ElevatedFailureRate {
        return TierElevated
    }
    return TierNormal
}

// GetCurrentDifficulty returns the current difficulty bits and expiration
func (dc *DifficultyController) GetCurrentDifficulty() (bits uint32, expiration time.Duration) {
    dc.mu.RLock()
    defer dc.mu.RUnlock()

    return dc.currentTier.Bits(), dc.currentTier.Expiration()
}
```

### Tier Transitions

```
                    ┌─────────────────────────────────────────┐
                    │           Tier State Machine            │
                    └─────────────────────────────────────────┘

    ┌────────┐  >10/min OR >10% fail   ┌──────────┐
    │ Normal │ ───────────────────────▶│ Elevated │
    │ 16 bit │ ◀─────────────────────── │  20 bit  │
    └────────┘  <10/min AND <10% fail  └──────────┘
                   (after 5min)              │
                                             │ >50/min OR >30% fail
                                             ▼
    ┌──────────┐  >100/min OR >50% fail ┌────────┐
    │   High   │ ──────────────────────▶│Critical│
    │  24 bit  │ ◀────────────────────── │ 28 bit │
    └──────────┘  <100/min AND <50% fail└────────┘
         ▲            (after 5min)
         │
         │ <50/min AND <30% fail (after 5min)
         │
    ┌──────────┐
    │ Elevated │
    └──────────┘

    Escalation: Immediate
    De-escalation: One tier per cooldown period (5 min)
```

---

## 4. Nonce Store

### Core Structures

```go
// internal/antispam/nonce.go

type NonceStore struct {
    mu       sync.RWMutex
    nonces   map[string]*nonceRecord  // Keyed by hex(nonce)

    // Cleanup
    cleanupInterval time.Duration
    stopCleanup     chan struct{}
}

type nonceRecord struct {
    nonce      []byte
    difficulty uint32
    createdAt  time.Time
    expiresAt  time.Time
    peerID     peer.ID
    used       bool  // Prevents replay
}

const (
    NonceLength     = 16
    CleanupInterval = 30 * time.Second
)

func NewNonceStore() *NonceStore {
    ns := &NonceStore{
        nonces:          make(map[string]*nonceRecord),
        cleanupInterval: CleanupInterval,
        stopCleanup:     make(chan struct{}),
    }
    go ns.cleanupLoop()
    return ns
}
```

### Nonce Generation

```go
// GenerateChallenge creates a new challenge with fresh nonce
func (ns *NonceStore) GenerateChallenge(peerID peer.ID, difficulty uint32, expiration time.Duration) (*PoWChallenge, error) {
    nonce := make([]byte, NonceLength)
    if _, err := rand.Read(nonce); err != nil {
        return nil, fmt.Errorf("generate nonce: %w", err)
    }

    now := time.Now()

    record := &nonceRecord{
        nonce:      nonce,
        difficulty: difficulty,
        createdAt:  now,
        expiresAt:  now.Add(expiration),
        peerID:     peerID,
        used:       false,
    }

    ns.mu.Lock()
    ns.nonces[hex.EncodeToString(nonce)] = record
    ns.mu.Unlock()

    return &PoWChallenge{
        Nonce:      nonce,
        Timestamp:  now.UnixMilli(),
        Difficulty: difficulty,
        PeerId:     []byte(peerID),
    }, nil
}
```

### Nonce Validation

```go
// ValidateAndConsume checks the nonce exists, is not expired, not used, and marks it consumed
func (ns *NonceStore) ValidateAndConsume(nonce []byte, peerID peer.ID) (*nonceRecord, error) {
    ns.mu.Lock()
    defer ns.mu.Unlock()

    key := hex.EncodeToString(nonce)
    record, exists := ns.nonces[key]

    if !exists {
        return nil, fmt.Errorf("unknown nonce")
    }

    // Check peer binding
    if record.peerID != peerID {
        return nil, fmt.Errorf("nonce bound to different peer")
    }

    // Check expiration
    if time.Now().After(record.expiresAt) {
        delete(ns.nonces, key)
        return nil, fmt.Errorf("nonce expired")
    }

    // Check replay
    if record.used {
        return nil, fmt.Errorf("nonce already used")
    }

    // Mark as used (consume)
    record.used = true

    return record, nil
}
```

### Cleanup Loop

```go
// cleanupLoop periodically evicts expired nonces
func (ns *NonceStore) cleanupLoop() {
    ticker := time.NewTicker(ns.cleanupInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ns.stopCleanup:
            return
        case <-ticker.C:
            ns.evictExpired()
        }
    }
}

func (ns *NonceStore) evictExpired() {
    ns.mu.Lock()
    defer ns.mu.Unlock()

    now := time.Now()
    evicted := 0

    for key, record := range ns.nonces {
        // Evict if expired OR used (no longer needed)
        if now.After(record.expiresAt) || record.used {
            delete(ns.nonces, key)
            evicted++
        }
    }

    if evicted > 0 {
        slog.Debug("evicted stale nonces", "count", evicted, "remaining", len(ns.nonces))
    }
}

func (ns *NonceStore) Stop() {
    close(ns.stopCleanup)
}

// Stats returns current nonce store statistics
func (ns *NonceStore) Stats() (total, pending, used int) {
    ns.mu.RLock()
    defer ns.mu.RUnlock()

    for _, record := range ns.nonces {
        total++
        if record.used {
            used++
        } else {
            pending++
        }
    }
    return
}
```

### Memory Bounds

```go
// internal/antispam/bounds.go

const (
    MaxPendingNonces = 10000  // Hard cap to prevent memory exhaustion
)

// GenerateChallenge with bounds checking
func (ns *NonceStore) GenerateChallenge(peerID peer.ID, difficulty uint32, expiration time.Duration) (*PoWChallenge, error) {
    ns.mu.Lock()

    // Check memory bounds before generating
    pendingCount := 0
    for _, r := range ns.nonces {
        if !r.used {
            pendingCount++
        }
    }

    if pendingCount >= MaxPendingNonces {
        ns.mu.Unlock()
        return nil, fmt.Errorf("nonce store at capacity: %d pending", pendingCount)
    }
    ns.mu.Unlock()

    // ... rest of generation logic
}
```

---

## 5. Handshake Integration

### Anti-Spam Service

```go
// internal/antispam/service.go

type AntiSpamService struct {
    controller *DifficultyController
    nonceStore *NonceStore

    // Metrics export
    onTierChange func(tier DifficultyTier)
}

func NewAntiSpamService(config DifficultyConfig) *AntiSpamService {
    return &AntiSpamService{
        controller: NewDifficultyController(config),
        nonceStore: NewNonceStore(),
    }
}

// IssueChallenge creates a challenge for an incoming handshake request
func (as *AntiSpamService) IssueChallenge(peerID peer.ID) (*PoWChallenge, error) {
    bits, expiration := as.controller.GetCurrentDifficulty()
    return as.nonceStore.GenerateChallenge(peerID, bits, expiration)
}

// VerifyResponse validates a PoW solution and records the outcome
func (as *AntiSpamService) VerifyResponse(
    challenge *PoWChallenge,
    solution *PoWSolution,
    proverPeerID peer.ID,
) error {
    // Validate nonce exists and is fresh
    record, err := as.nonceStore.ValidateAndConsume(challenge.Nonce, proverPeerID)
    if err != nil {
        as.controller.RecordChallenge(false)
        return fmt.Errorf("nonce validation failed: %w", err)
    }

    // Check timestamp within window
    challengeTime := time.UnixMilli(challenge.Timestamp)
    if time.Since(challengeTime) > record.expiresAt.Sub(record.createdAt) {
        as.controller.RecordChallenge(false)
        return fmt.Errorf("challenge expired")
    }

    // Verify the proof
    if err := Verify(challenge, solution, []byte(proverPeerID)); err != nil {
        as.controller.RecordChallenge(false)
        return fmt.Errorf("proof verification failed: %w", err)
    }

    // Success
    as.controller.RecordChallenge(true)
    return nil
}

func (as *AntiSpamService) Stop() {
    as.nonceStore.Stop()
}

func (as *AntiSpamService) GetCurrentTier() DifficultyTier {
    bits, _ := as.controller.GetCurrentDifficulty()
    switch bits {
    case 16:
        return TierNormal
    case 20:
        return TierElevated
    case 24:
        return TierHigh
    default:
        return TierCritical
    }
}
```

### Handshake Stage 1 Integration

```go
// internal/handshake/attestation.go

// handleIncomingHandshake processes Stage 1 for responder
func (m *Manager) handleIncomingHandshake(stream network.Stream) error {
    peerID := stream.Conn().RemotePeer()

    // Issue PoW challenge
    challenge, err := m.antiSpam.IssueChallenge(peerID)
    if err != nil {
        slog.Warn("failed to issue challenge", "peer", peerID, "error", err)
        return err
    }

    // Send challenge
    if err := writeMessage(stream, challenge); err != nil {
        return fmt.Errorf("send challenge: %w", err)
    }

    // Set read deadline based on difficulty
    _, expiration := m.antiSpam.controller.GetCurrentDifficulty()
    stream.SetReadDeadline(time.Now().Add(expiration + 5*time.Second))

    // Receive solution
    var solution PoWSolution
    if err := readMessage(stream, &solution); err != nil {
        m.antiSpam.controller.RecordChallenge(false)
        return fmt.Errorf("receive solution: %w", err)
    }

    // Verify
    if err := m.antiSpam.VerifyResponse(challenge, &solution, peerID); err != nil {
        sendResult(stream, &PoWResult{Valid: false, Error: err.Error()})
        return fmt.Errorf("verification failed: %w", err)
    }

    // Success - proceed to Stage 2
    sendResult(stream, &PoWResult{Valid: true})
    return m.proceedToVectorMatch(stream, peerID)
}

// initiateHandshake processes Stage 1 for initiator
func (m *Manager) initiateHandshake(peerID peer.ID) error {
    stream, err := m.host.NewStream(context.Background(), peerID, HandshakeProtocol)
    if err != nil {
        return fmt.Errorf("open stream: %w", err)
    }
    defer stream.Close()

    // Receive challenge
    var challenge PoWChallenge
    if err := readMessage(stream, &challenge); err != nil {
        return fmt.Errorf("receive challenge: %w", err)
    }

    slog.Info("received PoW challenge",
        "peer", peerID,
        "difficulty", challenge.Difficulty,
    )

    // Mine solution
    miner := &Miner{maxIterations: 1 << 32}
    result, err := miner.Mine(&challenge, []byte(m.host.ID()))
    if err != nil {
        return fmt.Errorf("mining failed: %w", err)
    }

    slog.Info("mined PoW solution",
        "peer", peerID,
        "counter", result.Counter,
        "elapsed", result.Elapsed,
    )

    // Send solution
    solution := &PoWSolution{
        ChallengeNonce:     challenge.Nonce,
        ChallengeTimestamp: challenge.Timestamp,
        Counter:            result.Counter,
        Proof:              result.Proof,
    }
    if err := writeMessage(stream, solution); err != nil {
        return fmt.Errorf("send solution: %w", err)
    }

    // Receive result
    var powResult PoWResult
    if err := readMessage(stream, &powResult); err != nil {
        return fmt.Errorf("receive result: %w", err)
    }

    if !powResult.Valid {
        return fmt.Errorf("PoW rejected: %s", powResult.Error)
    }

    // Success - proceed to Stage 2
    return m.proceedToVectorMatch(stream, peerID)
}
```

### Agent Daemon Integration

```go
// cmd/mymonad-agent/daemon.go

func (d *Daemon) initAntiSpam() {
    config := antispam.DifficultyConfig{
        WindowDuration:          time.Minute,
        CooldownDuration:        5 * time.Minute,
        ElevatedRateThreshold:   10,
        ElevatedFailureRate:     0.10,
        HighRateThreshold:       50,
        HighFailureRate:         0.30,
        CriticalRateThreshold:   100,
        CriticalFailureRate:     0.50,
    }

    d.antiSpam = antispam.NewAntiSpamService(config)
    d.handshakeMgr.SetAntiSpamService(d.antiSpam)

    // Optional: log tier changes
    d.antiSpam.onTierChange = func(tier antispam.DifficultyTier) {
        slog.Warn("anti-spam difficulty changed",
            "tier", tier,
            "bits", tier.Bits(),
        )
    }
}

func (d *Daemon) Shutdown() {
    d.antiSpam.Stop()
    // ... other cleanup
}
```

---

## 6. Testing Strategy

### Unit Tests: Mining & Verification

```go
// pkg/hashcash/miner_test.go

func TestMiner_FindsValidSolution(t *testing.T) {
    miner := &Miner{maxIterations: 1 << 24}

    challenge := &PoWChallenge{
        Nonce:      makeNonce(16),
        Timestamp:  time.Now().UnixMilli(),
        Difficulty: 16,
        PeerId:     []byte("test-peer"),
    }

    result, err := miner.Mine(challenge, []byte("prover-peer"))
    require.NoError(t, err)
    require.NotNil(t, result)

    // Verify the proof has required leading zeros
    leadingZeros := countLeadingZeroBits(result.Proof)
    require.GreaterOrEqual(t, leadingZeros, int(challenge.Difficulty))
}

func TestMiner_DifficultyAffectsTime(t *testing.T) {
    miner := &Miner{maxIterations: 1 << 28}

    // Mine at 16 bits
    challenge16 := &PoWChallenge{
        Nonce:      makeNonce(16),
        Timestamp:  time.Now().UnixMilli(),
        Difficulty: 16,
    }
    result16, _ := miner.Mine(challenge16, []byte("peer"))

    // Mine at 20 bits
    challenge20 := &PoWChallenge{
        Nonce:      makeNonce(16),
        Timestamp:  time.Now().UnixMilli(),
        Difficulty: 20,
    }
    result20, _ := miner.Mine(challenge20, []byte("peer"))

    // 20 bits should take roughly 16x longer (2^4)
    // Allow wide margin due to randomness
    require.Greater(t, result20.Elapsed, result16.Elapsed)
}

func TestVerify_ValidSolution(t *testing.T) {
    miner := &Miner{maxIterations: 1 << 24}
    proverID := []byte("prover-peer")

    challenge := &PoWChallenge{
        Nonce:      makeNonce(16),
        Timestamp:  time.Now().UnixMilli(),
        Difficulty: 16,
        PeerId:     []byte("verifier"),
    }

    result, _ := miner.Mine(challenge, proverID)

    solution := &PoWSolution{
        ChallengeNonce:     challenge.Nonce,
        ChallengeTimestamp: challenge.Timestamp,
        Counter:            result.Counter,
        Proof:              result.Proof,
    }

    err := Verify(challenge, solution, proverID)
    require.NoError(t, err)
}

func TestVerify_RejectsTamperedProof(t *testing.T) {
    miner := &Miner{maxIterations: 1 << 24}
    proverID := []byte("prover-peer")

    challenge := &PoWChallenge{
        Nonce:      makeNonce(16),
        Timestamp:  time.Now().UnixMilli(),
        Difficulty: 16,
    }

    result, _ := miner.Mine(challenge, proverID)

    // Tamper with proof
    result.Proof[0] ^= 0xFF

    solution := &PoWSolution{
        ChallengeNonce:     challenge.Nonce,
        ChallengeTimestamp: challenge.Timestamp,
        Counter:            result.Counter,
        Proof:              result.Proof,
    }

    err := Verify(challenge, solution, proverID)
    require.Error(t, err)
    require.Contains(t, err.Error(), "hash mismatch")
}

func TestVerify_RejectsWrongPeerID(t *testing.T) {
    miner := &Miner{maxIterations: 1 << 24}

    challenge := &PoWChallenge{
        Nonce:      makeNonce(16),
        Timestamp:  time.Now().UnixMilli(),
        Difficulty: 16,
    }

    // Mine with one peer ID
    result, _ := miner.Mine(challenge, []byte("prover-a"))

    solution := &PoWSolution{
        ChallengeNonce:     challenge.Nonce,
        ChallengeTimestamp: challenge.Timestamp,
        Counter:            result.Counter,
        Proof:              result.Proof,
    }

    // Verify with different peer ID
    err := Verify(challenge, solution, []byte("prover-b"))
    require.Error(t, err)
}
```

### Unit Tests: Difficulty Controller

```go
// internal/antispam/controller_test.go

func TestDifficultyController_StartsAtNormal(t *testing.T) {
    dc := NewDifficultyController(DefaultConfig())

    bits, _ := dc.GetCurrentDifficulty()
    require.Equal(t, uint32(16), bits)
}

func TestDifficultyController_EscalatesToElevated(t *testing.T) {
    dc := NewDifficultyController(DefaultConfig())

    // Simulate 11 challenges (>10 threshold)
    for i := 0; i < 11; i++ {
        dc.RecordChallenge(true)
    }

    bits, _ := dc.GetCurrentDifficulty()
    require.Equal(t, uint32(20), bits)
}

func TestDifficultyController_EscalatesOnFailureRate(t *testing.T) {
    dc := NewDifficultyController(DefaultConfig())

    // 5 successes, 2 failures = 28% failure rate (>10% threshold)
    for i := 0; i < 5; i++ {
        dc.RecordChallenge(true)
    }
    for i := 0; i < 2; i++ {
        dc.RecordChallenge(false)
    }

    bits, _ := dc.GetCurrentDifficulty()
    require.Equal(t, uint32(20), bits)
}

func TestDifficultyController_EscalatesToCritical(t *testing.T) {
    dc := NewDifficultyController(DefaultConfig())

    // Simulate 101 challenges with >50% failure
    for i := 0; i < 50; i++ {
        dc.RecordChallenge(true)
    }
    for i := 0; i < 51; i++ {
        dc.RecordChallenge(false)
    }

    bits, _ := dc.GetCurrentDifficulty()
    require.Equal(t, uint32(28), bits)
}

func TestDifficultyController_DeescalatesAfterCooldown(t *testing.T) {
    cfg := DefaultConfig()
    cfg.CooldownDuration = 100 * time.Millisecond  // Fast cooldown for test
    dc := NewDifficultyController(cfg)

    // Escalate to Elevated
    for i := 0; i < 15; i++ {
        dc.RecordChallenge(true)
    }
    require.Equal(t, uint32(20), dc.currentTier.Bits())

    // Wait for cooldown
    time.Sleep(150 * time.Millisecond)

    // Record low activity (triggers recalculation)
    dc.RecordChallenge(true)

    bits, _ := dc.GetCurrentDifficulty()
    require.Equal(t, uint32(16), bits)
}

func TestDifficultyController_NoDeescalateBeforeCooldown(t *testing.T) {
    dc := NewDifficultyController(DefaultConfig())

    // Escalate
    for i := 0; i < 15; i++ {
        dc.RecordChallenge(true)
    }
    require.Equal(t, uint32(20), dc.currentTier.Bits())

    // Immediately try to de-escalate (no cooldown elapsed)
    dc.challenges = nil  // Clear window
    dc.RecordChallenge(true)

    // Should still be Elevated
    bits, _ := dc.GetCurrentDifficulty()
    require.Equal(t, uint32(20), bits)
}

func TestDifficultyTier_Expiration(t *testing.T) {
    require.Equal(t, 30*time.Second, TierNormal.Expiration())
    require.Equal(t, 60*time.Second, TierElevated.Expiration())
    require.Equal(t, 90*time.Second, TierHigh.Expiration())
    require.Equal(t, 120*time.Second, TierCritical.Expiration())
}
```

### Unit Tests: Nonce Store

```go
// internal/antispam/nonce_test.go

func TestNonceStore_GenerateUnique(t *testing.T) {
    ns := NewNonceStore()
    defer ns.Stop()

    c1, _ := ns.GenerateChallenge("peer1", 16, 30*time.Second)
    c2, _ := ns.GenerateChallenge("peer1", 16, 30*time.Second)

    require.NotEqual(t, c1.Nonce, c2.Nonce)
}

func TestNonceStore_ValidateAndConsume(t *testing.T) {
    ns := NewNonceStore()
    defer ns.Stop()

    challenge, _ := ns.GenerateChallenge("peer1", 16, 30*time.Second)

    record, err := ns.ValidateAndConsume(challenge.Nonce, "peer1")
    require.NoError(t, err)
    require.True(t, record.used)
}

func TestNonceStore_RejectsReplay(t *testing.T) {
    ns := NewNonceStore()
    defer ns.Stop()

    challenge, _ := ns.GenerateChallenge("peer1", 16, 30*time.Second)

    // First use succeeds
    _, err := ns.ValidateAndConsume(challenge.Nonce, "peer1")
    require.NoError(t, err)

    // Second use fails (replay)
    _, err = ns.ValidateAndConsume(challenge.Nonce, "peer1")
    require.Error(t, err)
    require.Contains(t, err.Error(), "already used")
}

func TestNonceStore_RejectsExpired(t *testing.T) {
    ns := NewNonceStore()
    defer ns.Stop()

    challenge, _ := ns.GenerateChallenge("peer1", 16, 50*time.Millisecond)

    // Wait for expiration
    time.Sleep(100 * time.Millisecond)

    _, err := ns.ValidateAndConsume(challenge.Nonce, "peer1")
    require.Error(t, err)
    require.Contains(t, err.Error(), "expired")
}

func TestNonceStore_RejectsWrongPeer(t *testing.T) {
    ns := NewNonceStore()
    defer ns.Stop()

    challenge, _ := ns.GenerateChallenge("peer1", 16, 30*time.Second)

    _, err := ns.ValidateAndConsume(challenge.Nonce, "peer2")
    require.Error(t, err)
    require.Contains(t, err.Error(), "different peer")
}

func TestNonceStore_RejectsUnknown(t *testing.T) {
    ns := NewNonceStore()
    defer ns.Stop()

    _, err := ns.ValidateAndConsume([]byte("unknown-nonce"), "peer1")
    require.Error(t, err)
    require.Contains(t, err.Error(), "unknown nonce")
}

func TestNonceStore_EnforcesCapacity(t *testing.T) {
    ns := NewNonceStore()
    defer ns.Stop()

    // Fill to capacity
    for i := 0; i < MaxPendingNonces; i++ {
        _, err := ns.GenerateChallenge(peer.ID(fmt.Sprintf("peer%d", i)), 16, time.Hour)
        require.NoError(t, err)
    }

    // Next should fail
    _, err := ns.GenerateChallenge("overflow-peer", 16, time.Hour)
    require.Error(t, err)
    require.Contains(t, err.Error(), "at capacity")
}
```

### Integration Tests

```go
// tests/antispam_integration_test.go

func TestAntiSpam_FullChallengeResponse(t *testing.T) {
    service := antispam.NewAntiSpamService(antispam.DefaultConfig())
    defer service.Stop()

    proverID := peer.ID("prover-peer")

    // Issue challenge
    challenge, err := service.IssueChallenge(proverID)
    require.NoError(t, err)

    // Mine solution
    miner := &hashcash.Miner{MaxIterations: 1 << 24}
    result, err := miner.Mine(challenge, []byte(proverID))
    require.NoError(t, err)

    // Submit solution
    solution := &pow.PoWSolution{
        ChallengeNonce:     challenge.Nonce,
        ChallengeTimestamp: challenge.Timestamp,
        Counter:            result.Counter,
        Proof:              result.Proof,
    }

    err = service.VerifyResponse(challenge, solution, proverID)
    require.NoError(t, err)
}

func TestAntiSpam_DifficultyEscalationUnderLoad(t *testing.T) {
    service := antispam.NewAntiSpamService(antispam.DefaultConfig())
    defer service.Stop()

    // Verify starts at Normal
    require.Equal(t, antispam.TierNormal, service.GetCurrentTier())

    // Simulate spam attack (many failures)
    for i := 0; i < 20; i++ {
        challenge, _ := service.IssueChallenge(peer.ID(fmt.Sprintf("attacker%d", i)))

        // Submit invalid solution
        badSolution := &pow.PoWSolution{
            ChallengeNonce: challenge.Nonce,
            Counter:        0,
            Proof:          []byte("invalid"),
        }
        service.VerifyResponse(challenge, badSolution, peer.ID(fmt.Sprintf("attacker%d", i)))
    }

    // Should have escalated
    tier := service.GetCurrentTier()
    require.Greater(t, tier, antispam.TierNormal)
}
```

### Test Coverage Targets

| Component | Target | Focus Areas |
|-----------|--------|-------------|
| `miner.go` | 90% | Solution finding, difficulty levels |
| `verifier.go` | 95% | All validation paths, tampering detection |
| `controller.go` | 90% | Tier transitions, cooldown behavior |
| `nonce.go` | 90% | Generation, validation, expiration, replay |
| `service.go` | 85% | Integration, error propagation |
| Integration | N/A | Full challenge-response, escalation under load |

---

## 7. Implementation Tasks

### Task 1: Protocol Buffer Definitions

**Files:**
- Create: `api/proto/pow.proto`

**Steps:**
1. Write protobuf definitions for PoWChallenge, PoWSolution, PoWResult
2. Run `make proto` to generate Go code
3. Commit

### Task 2: Mining Implementation

**Files:**
- Create: `pkg/hashcash/miner.go`
- Create: `pkg/hashcash/miner_test.go`

**Steps:**
1. Write failing tests for Mine function
2. Implement buildPrefix, difficultyTarget, meetsTarget helpers
3. Implement Mine with counter iteration
4. Write tests for different difficulty levels
5. Commit

### Task 3: Verification Implementation

**Files:**
- Create: `pkg/hashcash/verifier.go`
- Create: `pkg/hashcash/verifier_test.go`

**Steps:**
1. Write failing tests for Verify function
2. Implement Verify with all validation checks
3. Write tests for tampering, wrong peer ID, wrong nonce
4. Commit

### Task 4: Difficulty Controller

**Files:**
- Create: `internal/antispam/controller.go`
- Create: `internal/antispam/controller_test.go`

**Steps:**
1. Define DifficultyTier enum with Bits() and Expiration()
2. Write failing tests for tier escalation
3. Implement RecordChallenge with sliding window
4. Implement recalculateTier with escalation/de-escalation logic
5. Write tests for cooldown behavior
6. Commit

### Task 5: Nonce Store

**Files:**
- Create: `internal/antispam/nonce.go`
- Create: `internal/antispam/nonce_test.go`

**Steps:**
1. Write failing tests for GenerateChallenge
2. Implement nonce generation with peer binding
3. Write failing tests for ValidateAndConsume
4. Implement validation with replay prevention
5. Implement cleanup loop
6. Write tests for capacity limits
7. Commit

### Task 6: Anti-Spam Service

**Files:**
- Create: `internal/antispam/service.go`
- Create: `internal/antispam/service_test.go`

**Steps:**
1. Write failing tests for IssueChallenge
2. Implement IssueChallenge integrating controller and nonce store
3. Write failing tests for VerifyResponse
4. Implement VerifyResponse with metric recording
5. Commit

### Task 7: Handshake Integration

**Files:**
- Modify: `internal/handshake/manager.go`
- Create: `internal/handshake/attestation.go`
- Create: `internal/handshake/attestation_test.go`

**Steps:**
1. Add SetAntiSpamService to Manager
2. Write failing tests for handleIncomingHandshake (responder)
3. Implement Stage 1 responder flow
4. Write failing tests for initiateHandshake (initiator)
5. Implement Stage 1 initiator flow with mining
6. Commit

### Task 8: Agent Integration

**Files:**
- Modify: `cmd/mymonad-agent/daemon.go`

**Steps:**
1. Add initAntiSpam function
2. Wire anti-spam service to handshake manager
3. Add tier change logging callback
4. Add shutdown cleanup
5. Commit

### Task 9: Integration Tests

**Files:**
- Create: `tests/antispam_integration_test.go`

**Steps:**
1. Write full challenge-response test
2. Write difficulty escalation under load test
3. Write replay attack rejection test
4. Write expiration test
5. Commit

---

## 8. Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Pre-computation | Server nonce prevents mining before challenge |
| Replay attacks | Nonce consumed on use, single-use enforcement |
| DoS via challenge flooding | MaxPendingNonces capacity limit (10,000) |
| Difficulty manipulation | Metrics-based calculation, not peer-influenced |
| Clock skew exploitation | Timestamp validation with expiration window |

### Attack Scenarios

| Attack | Defense |
|--------|---------|
| Spam handshake requests | Difficulty auto-escalates to 28 bits (~4s per attempt) |
| Solution reuse | Nonce store marks used, rejects duplicates |
| Challenge hoarding | Nonces expire per difficulty tier (30-120s) |
| Burst then pause | 5-minute cooldown prevents rapid de-escalation |
| Peer ID spoofing | Challenge bound to peer ID, verified in proof |

---

## 9. Operational Considerations

### Monitoring

```go
// Expose metrics for observability
type AntiSpamMetrics struct {
    CurrentTier       DifficultyTier
    ChallengesIssued  uint64
    ChallengesVerified uint64
    ChallengesFailed  uint64
    PendingNonces     int
    FailureRate       float64
}

func (as *AntiSpamService) Metrics() AntiSpamMetrics {
    // ... collect and return metrics
}
```

### Recommended Alerts

| Condition | Action |
|-----------|--------|
| Tier >= High for >10 min | Investigate potential attack |
| Pending nonces >8000 | Capacity warning |
| Failure rate >40% sustained | Check for misconfigured clients |

### Tuning Parameters

| Parameter | Default | Tuning Guidance |
|-----------|---------|-----------------|
| WindowDuration | 1 min | Shorter = more responsive, noisier |
| CooldownDuration | 5 min | Shorter = faster recovery, less protection |
| ElevatedRateThreshold | 10/min | Lower = more aggressive, may impact legitimate traffic |
| MaxPendingNonces | 10,000 | Higher = more memory, handles larger bursts |

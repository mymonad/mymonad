# Human Chat Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable encrypted direct messaging between humans during Stage 4 of the handshake protocol, with zero persistence and secure cleanup.

**Architecture:** Dedicated `/mymonad/chat/1.0.0` libp2p stream, cryptographically bound to Session.ID via HKDF-derived keys, with RAM-only message buffering.

**Tech Stack:** libp2p (streams), HKDF/SHA-256 (key derivation), AES-256-GCM (encryption), Protocol Buffers (messages)

---

## 1. Overview

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Human Chat System                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │   CLI/UI     │◀──▶│    Chat      │◀──▶│  Handshake   │              │
│  │  (human)     │    │   Service    │    │   Session    │              │
│  └──────────────┘    └──────────────┘    └──────────────┘              │
│         │                   │                   │                       │
│         │ IPC               │ Session.ID        │ SharedSecret          │
│         ▼                   ▼                   ▼                       │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │   Message    │    │    HKDF      │    │   Stream     │              │
│  │   Buffer     │    │  Key Deriv   │    │   Handler    │              │
│  │  (RAM only)  │    └──────────────┘    └──────────────┘              │
│  └──────────────┘           │                   │                       │
│                             │ ChatKey           │ /mymonad/chat/1.0.0   │
│                             ▼                   ▼                       │
│                      ┌─────────────────────────────┐                    │
│                      │     AES-256-GCM Encrypt     │                    │
│                      └─────────────────────────────┘                    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Transport | Dedicated `/mymonad/chat/1.0.0` stream | Independent of handshake state machine |
| Encryption | HKDF(SharedSecret, Session.ID) | Cryptographic binding, no redundant exchange |
| Delivery | ACK per message (hash) | Confirms decryption success for UI |
| Lifecycle | Survives session, dies on terminal | Robust to transient errors, clean termination |
| Content | Text + typing indicator | Essential UX with minimal complexity |
| Persistence | RAM only, wiped on Cleanup() | Zero persistence ethos |

### Integration Points

- **Handshake Session**: Provides SharedSecret and Session.ID for key derivation
- **Session Cleanup()**: Triggers chat buffer wipe and stream close
- **IPC**: Exposes SendMessage, ReceiveMessage, SendTyping to CLI/UI

---

## 2. Protocol Messages

### Protocol Buffer Definitions

```protobuf
// api/proto/chat.proto

syntax = "proto3";
package mymonad.chat;

option go_package = "github.com/mymonad/mymonad/api/proto/chat";

// ChatMessage is an encrypted text message
message ChatMessage {
  bytes message_id = 1;    // 16 bytes, random UUID for ACK correlation
  bytes ciphertext = 2;    // AES-256-GCM encrypted payload
  bytes nonce = 3;         // 12 bytes, unique per message
  int64 timestamp = 4;     // Unix milliseconds, for ordering in UI
}

// ChatAck confirms successful decryption
message ChatAck {
  bytes message_id = 1;    // Echoes the message_id being acknowledged
  bytes message_hash = 2;  // SHA-256(plaintext) to confirm correct decryption
}

// ChatTyping indicates typing status
message ChatTyping {
  bool is_typing = 1;      // true = started typing, false = stopped
}

// ChatEnvelope wraps all chat protocol messages
message ChatEnvelope {
  oneof payload {
    ChatMessage message = 1;
    ChatAck ack = 2;
    ChatTyping typing = 3;
  }
}
```

### Plaintext Message Structure

```protobuf
// Decrypted content of ChatMessage.ciphertext
message ChatPlaintext {
  string text = 1;         // UTF-8 message content, max 4096 bytes
  int64 sent_at = 2;       // Sender's local timestamp
}
```

### Key Derivation

```go
// internal/chat/crypto.go

const (
    ChatKeyInfo    = "mymonad-chat-v1"
    ChatKeyLength  = 32  // AES-256
    NonceLength    = 12  // GCM standard
    MaxMessageSize = 4096
)

// DeriveKey derives a chat-specific key from the handshake shared secret
func DeriveKey(sharedSecret []byte, sessionID []byte) ([]byte, error) {
    hkdf := hkdf.New(sha256.New, sharedSecret, sessionID, []byte(ChatKeyInfo))

    key := make([]byte, ChatKeyLength)
    if _, err := io.ReadFull(hkdf, key); err != nil {
        return nil, fmt.Errorf("derive chat key: %w", err)
    }
    return key, nil
}
```

### Message Flow

```
    Alice                                      Bob
      │                                          │
      │  ──── ChatEnvelope{typing: true} ──────▶ │
      │                                          │
      │  ──── ChatEnvelope{message} ───────────▶ │
      │       {id, ciphertext, nonce, ts}        │
      │                                          │
      │       [Bob decrypts, verifies]           │
      │                                          │
      │  ◀─── ChatEnvelope{ack} ─────────────── │
      │       {id, hash(plaintext)}              │
      │                                          │
      │       [Alice marks "delivered"]          │
      │                                          │
```

---

## 3. Chat Service & Buffer Management

### Core Structures

```go
// internal/chat/service.go

const (
    MaxBufferedMessages = 100  // Per session, oldest evicted on overflow
    MaxRetries          = 5    // Exceeding triggers session cleanup
)

type ChatService struct {
    mu           sync.RWMutex
    sessions     map[string]*ChatSession  // Keyed by Session.ID
    host         host.Host
    handshakeMgr *handshake.Manager
}

type ChatSession struct {
    mu            sync.RWMutex
    sessionID     []byte
    peerID        peer.ID
    chatKey       []byte              // Derived via HKDF
    stream        network.Stream      // /mymonad/chat/1.0.0

    // RAM-only message buffer ([]byte for secure wipe)
    messages      []*StoredMessage
    pendingAcks   map[string]*PendingMessage  // Keyed by message_id hex

    // State
    isOpen        bool
    peerTyping    bool
    lastActivity  time.Time

    // Callbacks
    onMessage     func(*ReceivedMessage)
    onTyping      func(bool)
    onDelivered   func(messageID []byte)
    onCleanup     func()  // Notify parent service
}

type StoredMessage struct {
    ID          []byte
    Plaintext   []byte    // []byte for secure zeroing
    SentAt      time.Time
    DeliveredAt *time.Time  // nil until ACK received
    Direction   MessageDirection  // Sent or Received
}

type PendingMessage struct {
    ID        []byte
    Plaintext []byte    // []byte for secure zeroing
    SentAt    time.Time
    Retries   int
}
```

### Stream Lifecycle

```go
// OpenChat establishes chat stream for an active handshake session
func (cs *ChatService) OpenChat(sessionID []byte) (*ChatSession, error) {
    cs.mu.Lock()
    defer cs.mu.Unlock()

    sidHex := hex.EncodeToString(sessionID)
    if existing, ok := cs.sessions[sidHex]; ok {
        return existing, nil  // Already open
    }

    // Get handshake session for shared secret and peer ID
    hsSession, err := cs.handshakeMgr.GetSession(sessionID)
    if err != nil {
        return nil, fmt.Errorf("handshake session not found: %w", err)
    }

    // Verify session is in Stage 4 (Human Chat) or later
    if hsSession.GetState() < handshake.StateHumanChat {
        return nil, fmt.Errorf("session not ready for chat: state=%v", hsSession.GetState())
    }

    // Derive chat key
    chatKey, err := DeriveKey(hsSession.GetSharedSecret(), sessionID)
    if err != nil {
        return nil, err
    }

    // Open dedicated chat stream
    stream, err := cs.host.NewStream(
        context.Background(),
        hsSession.GetPeerID(),
        protocol.ID("/mymonad/chat/1.0.0"),
    )
    if err != nil {
        return nil, fmt.Errorf("open chat stream: %w", err)
    }

    session := &ChatSession{
        sessionID:    sessionID,
        peerID:       hsSession.GetPeerID(),
        chatKey:      chatKey,
        stream:       stream,
        messages:     make([]*StoredMessage, 0),
        pendingAcks:  make(map[string]*PendingMessage),
        isOpen:       true,
        lastActivity: time.Now(),
    }

    cs.sessions[sidHex] = session
    go session.readLoop()

    return session, nil
}
```

### Retry Logic with Cleanup Trigger

```go
// retryPending attempts to resend unacknowledged messages
func (s *ChatSession) retryPending() {
    s.mu.Lock()
    defer s.mu.Unlock()

    for id, pending := range s.pendingAcks {
        pending.Retries++

        if pending.Retries > MaxRetries {
            slog.Error("max retries exceeded, cleaning up session",
                "session_id", hex.EncodeToString(s.sessionID),
                "message_id", id,
            )
            // Release lock before cleanup to avoid deadlock
            s.mu.Unlock()
            s.Cleanup()
            return
        }

        // Resend message
        if err := s.sendEncrypted(pending.ID, pending.Plaintext); err != nil {
            slog.Warn("retry failed", "message_id", id, "error", err)
        }
    }
}
```

### Buffer Management & Secure Cleanup

```go
// storeMessage adds to RAM buffer with size limit
func (s *ChatSession) storeMessage(msg *StoredMessage) {
    s.mu.Lock()
    defer s.mu.Unlock()

    // Evict and wipe oldest if over limit
    if len(s.messages) >= MaxBufferedMessages {
        evicted := s.messages[0]
        zeroFill(evicted.Plaintext)
        s.messages = s.messages[1:]
    }

    s.messages = append(s.messages, msg)
}

// zeroFill securely wipes a byte slice
func zeroFill(b []byte) {
    for i := range b {
        b[i] = 0
    }
}

// Cleanup wipes all chat data - called by handshake Session.Cleanup()
func (s *ChatSession) Cleanup() {
    s.mu.Lock()
    defer s.mu.Unlock()

    if !s.isOpen {
        return  // Already cleaned up
    }

    // Close stream
    if s.stream != nil {
        s.stream.Close()
        s.stream = nil
    }

    // Wipe key material
    zeroFill(s.chatKey)
    s.chatKey = nil

    // Wipe message buffer
    for _, msg := range s.messages {
        zeroFill(msg.Plaintext)
        zeroFill(msg.ID)
    }
    s.messages = nil

    // Wipe pending messages
    for _, pending := range s.pendingAcks {
        zeroFill(pending.Plaintext)
        zeroFill(pending.ID)
    }
    s.pendingAcks = nil

    // Wipe session ID
    zeroFill(s.sessionID)

    s.isOpen = false

    // Notify parent service
    if s.onCleanup != nil {
        s.onCleanup()
    }
}

// RegisterCleanup hooks into handshake session lifecycle
func (cs *ChatService) RegisterCleanup(sessionID []byte) {
    cs.handshakeMgr.OnSessionTerminal(sessionID, func() {
        cs.mu.Lock()
        sidHex := hex.EncodeToString(sessionID)
        if session, ok := cs.sessions[sidHex]; ok {
            session.Cleanup()
            delete(cs.sessions, sidHex)
        }
        cs.mu.Unlock()
    })
}
```

---

## 4. Message Handling

### Sending Messages

```go
// internal/chat/send.go

// SendMessage encrypts and sends a text message
func (s *ChatSession) SendMessage(text string) ([]byte, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    if !s.isOpen {
        return nil, fmt.Errorf("chat session closed")
    }

    if len(text) > MaxMessageSize {
        return nil, fmt.Errorf("message exceeds max size: %d > %d", len(text), MaxMessageSize)
    }

    // Generate message ID
    messageID := make([]byte, 16)
    if _, err := rand.Read(messageID); err != nil {
        return nil, fmt.Errorf("generate message id: %w", err)
    }

    // Serialize plaintext
    plaintext := &ChatPlaintext{
        Text:   text,
        SentAt: time.Now().UnixMilli(),
    }
    plaintextBytes, err := proto.Marshal(plaintext)
    if err != nil {
        return nil, fmt.Errorf("marshal plaintext: %w", err)
    }

    // Encrypt
    ciphertext, nonce, err := s.encrypt(plaintextBytes)
    if err != nil {
        zeroFill(plaintextBytes)
        return nil, fmt.Errorf("encrypt: %w", err)
    }

    // Build and send envelope
    envelope := &ChatEnvelope{
        Payload: &ChatEnvelope_Message{
            Message: &ChatMessage{
                MessageId:  messageID,
                Ciphertext: ciphertext,
                Nonce:      nonce,
                Timestamp:  time.Now().UnixMilli(),
            },
        },
    }

    if err := s.writeEnvelope(envelope); err != nil {
        zeroFill(plaintextBytes)
        return nil, fmt.Errorf("send message: %w", err)
    }

    // Store in buffer and pending ACKs
    stored := &StoredMessage{
        ID:        messageID,
        Plaintext: plaintextBytes,  // Ownership transferred
        SentAt:    time.Now(),
        Direction: DirectionSent,
    }
    s.messages = append(s.messages, stored)

    s.pendingAcks[hex.EncodeToString(messageID)] = &PendingMessage{
        ID:        messageID,
        Plaintext: plaintextBytes,
        SentAt:    time.Now(),
        Retries:   0,
    }

    s.lastActivity = time.Now()
    return messageID, nil
}

// encrypt uses AES-256-GCM with random nonce
func (s *ChatSession) encrypt(plaintext []byte) (ciphertext, nonce []byte, err error) {
    block, err := aes.NewCipher(s.chatKey)
    if err != nil {
        return nil, nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, nil, err
    }

    nonce = make([]byte, NonceLength)
    if _, err := rand.Read(nonce); err != nil {
        return nil, nil, err
    }

    ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
    return ciphertext, nonce, nil
}
```

### Receiving Messages

```go
// internal/chat/receive.go

// readLoop processes incoming chat envelopes
func (s *ChatSession) readLoop() {
    defer s.handleStreamClose()

    for {
        envelope, err := s.readEnvelope()
        if err != nil {
            if err != io.EOF {
                slog.Warn("chat read error", "error", err)
            }
            return
        }

        switch p := envelope.Payload.(type) {
        case *ChatEnvelope_Message:
            s.handleMessage(p.Message)
        case *ChatEnvelope_Ack:
            s.handleAck(p.Ack)
        case *ChatEnvelope_Typing:
            s.handleTyping(p.Typing)
        }
    }
}

func (s *ChatSession) handleMessage(msg *ChatMessage) {
    // Decrypt
    plaintext, err := s.decrypt(msg.Ciphertext, msg.Nonce)
    if err != nil {
        slog.Warn("failed to decrypt message", "error", err)
        return
    }

    // Parse plaintext
    var content ChatPlaintext
    if err := proto.Unmarshal(plaintext, &content); err != nil {
        slog.Warn("failed to parse plaintext", "error", err)
        zeroFill(plaintext)
        return
    }

    // Send ACK immediately after successful decryption
    ack := &ChatEnvelope{
        Payload: &ChatEnvelope_Ack{
            Ack: &ChatAck{
                MessageId:   msg.MessageId,
                MessageHash: sha256Sum(plaintext),
            },
        },
    }
    if err := s.writeEnvelope(ack); err != nil {
        slog.Warn("failed to send ack", "error", err)
    }

    // Store received message
    s.mu.Lock()
    s.storeMessageLocked(&StoredMessage{
        ID:        msg.MessageId,
        Plaintext: plaintext,  // Ownership transferred
        SentAt:    time.UnixMilli(content.SentAt),
        Direction: DirectionReceived,
    })
    s.lastActivity = time.Now()
    s.mu.Unlock()

    // Notify callback
    if s.onMessage != nil {
        s.onMessage(&ReceivedMessage{
            ID:   msg.MessageId,
            Text: content.Text,
            At:   time.UnixMilli(content.SentAt),
        })
    }
}

func (s *ChatSession) handleAck(ack *ChatAck) {
    s.mu.Lock()
    defer s.mu.Unlock()

    idHex := hex.EncodeToString(ack.MessageId)
    pending, ok := s.pendingAcks[idHex]
    if !ok {
        return  // Unknown or already ACKed
    }

    // Verify hash matches our plaintext
    expectedHash := sha256Sum(pending.Plaintext)
    if !bytes.Equal(ack.MessageHash, expectedHash) {
        slog.Warn("ack hash mismatch", "message_id", idHex)
        return
    }

    // Mark delivered
    delete(s.pendingAcks, idHex)
    now := time.Now()
    for _, msg := range s.messages {
        if bytes.Equal(msg.ID, ack.MessageId) {
            msg.DeliveredAt = &now
            break
        }
    }

    s.lastActivity = time.Now()

    // Notify callback
    if s.onDelivered != nil {
        s.onDelivered(ack.MessageId)
    }
}

func (s *ChatSession) decrypt(ciphertext, nonce []byte) ([]byte, error) {
    block, err := aes.NewCipher(s.chatKey)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    return gcm.Open(nil, nonce, ciphertext, nil)
}

func sha256Sum(data []byte) []byte {
    h := sha256.Sum256(data)
    return h[:]
}
```

### Typing Indicators

```go
// internal/chat/typing.go

const (
    TypingTimeout = 5 * time.Second  // Auto-clear peer typing after silence
)

// SendTyping sends typing status to peer
func (s *ChatSession) SendTyping(isTyping bool) error {
    s.mu.RLock()
    if !s.isOpen {
        s.mu.RUnlock()
        return fmt.Errorf("chat session closed")
    }
    s.mu.RUnlock()

    envelope := &ChatEnvelope{
        Payload: &ChatEnvelope_Typing{
            Typing: &ChatTyping{
                IsTyping: isTyping,
            },
        },
    }

    return s.writeEnvelope(envelope)
}

func (s *ChatSession) handleTyping(typing *ChatTyping) {
    s.mu.Lock()
    s.peerTyping = typing.IsTyping
    s.lastActivity = time.Now()
    s.mu.Unlock()

    if s.onTyping != nil {
        s.onTyping(typing.IsTyping)
    }

    // Auto-clear after timeout if no further updates
    if typing.IsTyping {
        go func() {
            time.Sleep(TypingTimeout)
            s.mu.Lock()
            if s.peerTyping && time.Since(s.lastActivity) >= TypingTimeout {
                s.peerTyping = false
                s.mu.Unlock()
                if s.onTyping != nil {
                    s.onTyping(false)
                }
            } else {
                s.mu.Unlock()
            }
        }()
    }
}
```

---

## 5. Error Handling & Edge Cases

### Error Types

```go
// internal/chat/errors.go

type ChatError string

const (
    ErrSessionClosed    ChatError = "session_closed"
    ErrMessageTooLarge  ChatError = "message_too_large"
    ErrDecryptionFailed ChatError = "decryption_failed"
    ErrStreamBroken     ChatError = "stream_broken"
    ErrMaxRetries       ChatError = "max_retries_exceeded"
    ErrInvalidState     ChatError = "invalid_handshake_state"
)

func (e ChatError) Error() string {
    return string(e)
}
```

### Stream Error Handling

```go
// internal/chat/stream.go

func (s *ChatSession) handleStreamClose() {
    s.mu.Lock()
    wasOpen := s.isOpen
    s.mu.Unlock()

    if wasOpen {
        slog.Info("chat stream closed",
            "session_id", hex.EncodeToString(s.sessionID),
            "peer", s.peerID,
        )
        s.Cleanup()
    }
}

func (s *ChatSession) writeEnvelope(env *ChatEnvelope) error {
    s.mu.RLock()
    stream := s.stream
    isOpen := s.isOpen
    s.mu.RUnlock()

    if !isOpen || stream == nil {
        return ErrSessionClosed
    }

    data, err := proto.Marshal(env)
    if err != nil {
        return fmt.Errorf("marshal envelope: %w", err)
    }

    // Length-prefixed write
    lenBuf := make([]byte, 4)
    binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))

    if _, err := stream.Write(lenBuf); err != nil {
        return fmt.Errorf("%w: %v", ErrStreamBroken, err)
    }
    if _, err := stream.Write(data); err != nil {
        return fmt.Errorf("%w: %v", ErrStreamBroken, err)
    }

    return nil
}

func (s *ChatSession) readEnvelope() (*ChatEnvelope, error) {
    s.mu.RLock()
    stream := s.stream
    s.mu.RUnlock()

    if stream == nil {
        return nil, ErrSessionClosed
    }

    // Length-prefixed read
    lenBuf := make([]byte, 4)
    if _, err := io.ReadFull(stream, lenBuf); err != nil {
        return nil, err
    }

    length := binary.BigEndian.Uint32(lenBuf)
    if length > MaxEnvelopeSize {
        return nil, fmt.Errorf("envelope too large: %d", length)
    }

    data := make([]byte, length)
    if _, err := io.ReadFull(stream, data); err != nil {
        return nil, err
    }

    var env ChatEnvelope
    if err := proto.Unmarshal(data, &env); err != nil {
        return nil, fmt.Errorf("unmarshal envelope: %w", err)
    }

    return &env, nil
}

const MaxEnvelopeSize = 8192  // 4KB message + overhead
```

### Handshake State Transitions

```go
// internal/chat/lifecycle.go

// monitorHandshakeState watches for terminal handshake states
func (cs *ChatService) monitorHandshakeState(sessionID []byte) {
    sidHex := hex.EncodeToString(sessionID)

    cs.handshakeMgr.OnStateChange(sessionID, func(newState handshake.State) {
        switch newState {
        case handshake.StateUnmasked:
            // Terminal success - cleanup chat
            slog.Info("handshake unmasked, closing chat", "session_id", sidHex)
            cs.closeSession(sidHex)

        case handshake.StateRejected, handshake.StateFailed:
            // Terminal failure - cleanup chat
            slog.Info("handshake terminated, closing chat",
                "session_id", sidHex,
                "state", newState,
            )
            cs.closeSession(sidHex)
        }
        // Non-terminal states (retries, renegotiation): chat survives
    })
}

func (cs *ChatService) closeSession(sidHex string) {
    cs.mu.Lock()
    defer cs.mu.Unlock()

    if session, ok := cs.sessions[sidHex]; ok {
        session.Cleanup()
        delete(cs.sessions, sidHex)
    }
}
```

### Edge Cases

| Scenario | Behavior |
|----------|----------|
| Stream breaks mid-message | readLoop exits, triggers Cleanup() |
| Peer sends oversized message | Reject, log warning, continue reading |
| Decryption fails | Log warning, skip message, do not ACK |
| ACK for unknown message | Ignore silently |
| ACK hash mismatch | Log warning, do not mark delivered |
| Handshake retries during chat | Chat survives, continues normally |
| Both parties send simultaneously | No issue - full duplex stream |
| Message sent after Cleanup() | Returns ErrSessionClosed |

### Reconnection Policy

```go
// Chat does NOT auto-reconnect. If stream breaks:
// 1. Cleanup() wipes all state
// 2. Human must re-initiate from CLI/UI
// 3. New chat session requires handshake still in Stage 4+

// This is intentional: zero-persistence means no "resume" capability.
// Each chat session is ephemeral and self-contained.
```

---

## 6. Testing Strategy

### Unit Tests: Encryption & Key Derivation

```go
// internal/chat/crypto_test.go

func TestDeriveKey_Deterministic(t *testing.T) {
    sharedSecret := make([]byte, 32)
    rand.Read(sharedSecret)
    sessionID := make([]byte, 16)
    rand.Read(sessionID)

    key1, err := DeriveKey(sharedSecret, sessionID)
    require.NoError(t, err)

    key2, err := DeriveKey(sharedSecret, sessionID)
    require.NoError(t, err)

    require.Equal(t, key1, key2, "same inputs must produce same key")
}

func TestDeriveKey_SessionBinding(t *testing.T) {
    sharedSecret := make([]byte, 32)
    rand.Read(sharedSecret)

    sessionA := []byte("session-a")
    sessionB := []byte("session-b")

    keyA, _ := DeriveKey(sharedSecret, sessionA)
    keyB, _ := DeriveKey(sharedSecret, sessionB)

    require.NotEqual(t, keyA, keyB, "different sessions must produce different keys")
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
    session := newTestChatSession()
    plaintext := []byte("hello, world")

    ciphertext, nonce, err := session.encrypt(plaintext)
    require.NoError(t, err)
    require.NotEqual(t, plaintext, ciphertext)

    decrypted, err := session.decrypt(ciphertext, nonce)
    require.NoError(t, err)
    require.Equal(t, plaintext, decrypted)
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
    session := newTestChatSession()
    plaintext := []byte("secret message")

    ciphertext, nonce, _ := session.encrypt(plaintext)

    // Tamper with ciphertext
    ciphertext[0] ^= 0xFF

    _, err := session.decrypt(ciphertext, nonce)
    require.Error(t, err, "tampered ciphertext must fail decryption")
}

func TestDecrypt_WrongNonce(t *testing.T) {
    session := newTestChatSession()
    plaintext := []byte("secret message")

    ciphertext, _, _ := session.encrypt(plaintext)
    wrongNonce := make([]byte, NonceLength)
    rand.Read(wrongNonce)

    _, err := session.decrypt(ciphertext, wrongNonce)
    require.Error(t, err, "wrong nonce must fail decryption")
}
```

### Unit Tests: Message Handling

```go
// internal/chat/message_test.go

func TestSendMessage_StoresInBuffer(t *testing.T) {
    session := newTestChatSession()

    msgID, err := session.SendMessage("test message")
    require.NoError(t, err)
    require.Len(t, msgID, 16)

    session.mu.RLock()
    require.Len(t, session.messages, 1)
    require.Equal(t, DirectionSent, session.messages[0].Direction)
    session.mu.RUnlock()
}

func TestSendMessage_AddsToPendingAcks(t *testing.T) {
    session := newTestChatSession()

    msgID, _ := session.SendMessage("test message")

    session.mu.RLock()
    pending, ok := session.pendingAcks[hex.EncodeToString(msgID)]
    session.mu.RUnlock()

    require.True(t, ok)
    require.Equal(t, 0, pending.Retries)
}

func TestSendMessage_RejectsOversized(t *testing.T) {
    session := newTestChatSession()

    oversized := string(make([]byte, MaxMessageSize+1))
    _, err := session.SendMessage(oversized)

    require.ErrorIs(t, err, ErrMessageTooLarge)
}

func TestSendMessage_RejectsClosedSession(t *testing.T) {
    session := newTestChatSession()
    session.Cleanup()

    _, err := session.SendMessage("test")
    require.ErrorIs(t, err, ErrSessionClosed)
}

func TestHandleAck_MarksDelivered(t *testing.T) {
    session := newTestChatSession()

    msgID, _ := session.SendMessage("test message")

    // Simulate ACK from peer
    session.mu.RLock()
    pending := session.pendingAcks[hex.EncodeToString(msgID)]
    session.mu.RUnlock()

    ack := &ChatAck{
        MessageId:   msgID,
        MessageHash: sha256Sum(pending.Plaintext),
    }
    session.handleAck(ack)

    session.mu.RLock()
    _, stillPending := session.pendingAcks[hex.EncodeToString(msgID)]
    msg := session.messages[0]
    session.mu.RUnlock()

    require.False(t, stillPending)
    require.NotNil(t, msg.DeliveredAt)
}

func TestHandleAck_RejectsHashMismatch(t *testing.T) {
    session := newTestChatSession()

    msgID, _ := session.SendMessage("test message")

    // ACK with wrong hash
    ack := &ChatAck{
        MessageId:   msgID,
        MessageHash: []byte("wrong-hash"),
    }
    session.handleAck(ack)

    session.mu.RLock()
    _, stillPending := session.pendingAcks[hex.EncodeToString(msgID)]
    session.mu.RUnlock()

    require.True(t, stillPending, "message must remain pending on hash mismatch")
}
```

### Unit Tests: Retry & Cleanup

```go
// internal/chat/retry_test.go

func TestRetryPending_IncrementsCounter(t *testing.T) {
    session := newTestChatSession()

    msgID, _ := session.SendMessage("test")

    session.retryPending()

    session.mu.RLock()
    pending := session.pendingAcks[hex.EncodeToString(msgID)]
    session.mu.RUnlock()

    require.Equal(t, 1, pending.Retries)
}

func TestRetryPending_TriggersCleanupOnMaxRetries(t *testing.T) {
    session := newTestChatSession()

    msgID, _ := session.SendMessage("test")

    // Set retries to max
    session.mu.Lock()
    session.pendingAcks[hex.EncodeToString(msgID)].Retries = MaxRetries
    session.mu.Unlock()

    session.retryPending()

    session.mu.RLock()
    isOpen := session.isOpen
    session.mu.RUnlock()

    require.False(t, isOpen, "session must be cleaned up after max retries")
}

func TestCleanup_ZerosAllSensitiveData(t *testing.T) {
    session := newTestChatSession()

    session.SendMessage("secret message 1")
    session.SendMessage("secret message 2")

    // Capture references before cleanup
    session.mu.RLock()
    chatKey := session.chatKey
    messages := session.messages
    plaintexts := make([][]byte, len(messages))
    for i, m := range messages {
        plaintexts[i] = m.Plaintext
    }
    session.mu.RUnlock()

    session.Cleanup()

    // Verify key is zeroed
    for _, b := range chatKey {
        require.Equal(t, byte(0), b, "chat key must be zeroed")
    }

    // Verify plaintexts are zeroed
    for _, pt := range plaintexts {
        for _, b := range pt {
            require.Equal(t, byte(0), b, "plaintext must be zeroed")
        }
    }
}

func TestCleanup_Idempotent(t *testing.T) {
    session := newTestChatSession()

    session.Cleanup()
    session.Cleanup()  // Should not panic

    require.False(t, session.isOpen)
}
```

### Unit Tests: Typing Indicators

```go
// internal/chat/typing_test.go

func TestHandleTyping_UpdatesState(t *testing.T) {
    session := newTestChatSession()

    session.handleTyping(&ChatTyping{IsTyping: true})

    session.mu.RLock()
    isTyping := session.peerTyping
    session.mu.RUnlock()

    require.True(t, isTyping)
}

func TestHandleTyping_CallsCallback(t *testing.T) {
    session := newTestChatSession()

    var received bool
    session.onTyping = func(isTyping bool) {
        received = isTyping
    }

    session.handleTyping(&ChatTyping{IsTyping: true})

    require.True(t, received)
}

func TestHandleTyping_AutoClearsAfterTimeout(t *testing.T) {
    session := newTestChatSession()

    session.handleTyping(&ChatTyping{IsTyping: true})

    // Wait for timeout
    time.Sleep(TypingTimeout + 100*time.Millisecond)

    session.mu.RLock()
    isTyping := session.peerTyping
    session.mu.RUnlock()

    require.False(t, isTyping, "typing must auto-clear after timeout")
}
```

### Integration Tests

```go
// tests/chat_integration_test.go

func TestChat_FullConversation(t *testing.T) {
    // Setup two agents with completed Stage 3 handshake
    alice, bob := setupHandshakedPair(t)

    aliceChat, err := alice.chatService.OpenChat(alice.sessionID)
    require.NoError(t, err)

    bobChat, err := bob.chatService.OpenChat(bob.sessionID)
    require.NoError(t, err)

    // Alice sends message
    var bobReceived *ReceivedMessage
    bobChat.onMessage = func(msg *ReceivedMessage) {
        bobReceived = msg
    }

    msgID, err := aliceChat.SendMessage("Hello Bob!")
    require.NoError(t, err)

    // Wait for delivery
    require.Eventually(t, func() bool {
        return bobReceived != nil
    }, time.Second, 10*time.Millisecond)

    require.Equal(t, "Hello Bob!", bobReceived.Text)

    // Wait for ACK
    require.Eventually(t, func() bool {
        aliceChat.mu.RLock()
        defer aliceChat.mu.RUnlock()
        _, pending := aliceChat.pendingAcks[hex.EncodeToString(msgID)]
        return !pending
    }, time.Second, 10*time.Millisecond)
}

func TestChat_CleanupOnUnmask(t *testing.T) {
    alice, bob := setupHandshakedPair(t)

    aliceChat, _ := alice.chatService.OpenChat(alice.sessionID)
    bobChat, _ := bob.chatService.OpenChat(bob.sessionID)

    // Trigger unmask (Stage 5 completion)
    alice.handshakeMgr.CompleteUnmask(alice.sessionID)

    // Both chat sessions should be cleaned up
    require.Eventually(t, func() bool {
        aliceChat.mu.RLock()
        defer aliceChat.mu.RUnlock()
        return !aliceChat.isOpen
    }, time.Second, 10*time.Millisecond)

    require.Eventually(t, func() bool {
        bobChat.mu.RLock()
        defer bobChat.mu.RUnlock()
        return !bobChat.isOpen
    }, time.Second, 10*time.Millisecond)
}
```

### Test Coverage Targets

| Component | Target | Focus Areas |
|-----------|--------|-------------|
| `crypto.go` | 95% | Key derivation, encrypt/decrypt, edge cases |
| `service.go` | 85% | Session management, lifecycle hooks |
| `send.go` | 90% | Message creation, buffer storage, pending tracking |
| `receive.go` | 90% | Decryption, ACK handling, callback dispatch |
| `typing.go` | 85% | State updates, timeout behavior |
| Integration | N/A | Full conversation, terminal state cleanup |

---

## 7. Implementation Tasks

### Task 1: Protocol Buffer Definitions

**Files:**
- Create: `api/proto/chat.proto`

**Steps:**
1. Write protobuf definitions for ChatMessage, ChatAck, ChatTyping, ChatEnvelope, ChatPlaintext
2. Run `make proto` to generate Go code
3. Commit

### Task 2: Key Derivation & Encryption

**Files:**
- Create: `internal/chat/crypto.go`
- Create: `internal/chat/crypto_test.go`

**Steps:**
1. Write failing tests for DeriveKey
2. Implement HKDF key derivation
3. Write failing tests for encrypt/decrypt
4. Implement AES-256-GCM encryption
5. Write tests for tampering detection
6. Commit

### Task 3: Chat Session Core

**Files:**
- Create: `internal/chat/session.go`
- Create: `internal/chat/session_test.go`

**Steps:**
1. Define ChatSession struct with []byte plaintext fields
2. Write failing tests for zeroFill
3. Implement zeroFill helper
4. Write failing tests for Cleanup
5. Implement Cleanup with secure zeroing
6. Write tests for idempotent cleanup
7. Commit

### Task 4: Chat Service

**Files:**
- Create: `internal/chat/service.go`
- Create: `internal/chat/service_test.go`

**Steps:**
1. Define ChatService struct
2. Write failing tests for OpenChat
3. Implement OpenChat with state validation
4. Write tests for duplicate session handling
5. Implement RegisterCleanup
6. Commit

### Task 5: Message Sending

**Files:**
- Create: `internal/chat/send.go`
- Create: `internal/chat/send_test.go`

**Steps:**
1. Write failing tests for SendMessage
2. Implement SendMessage with encryption
3. Write tests for buffer storage
4. Implement pending ACK tracking
5. Write tests for size validation
6. Commit

### Task 6: Message Receiving

**Files:**
- Create: `internal/chat/receive.go`
- Create: `internal/chat/receive_test.go`

**Steps:**
1. Write failing tests for handleMessage
2. Implement handleMessage with decryption and ACK
3. Write failing tests for handleAck
4. Implement handleAck with hash verification
5. Write tests for hash mismatch handling
6. Commit

### Task 7: Retry Logic

**Files:**
- Modify: `internal/chat/session.go`
- Create: `internal/chat/retry_test.go`

**Steps:**
1. Write failing tests for retryPending
2. Implement retryPending with counter increment
3. Write tests for MaxRetries cleanup trigger
4. Implement cleanup on MaxRetries exceeded
5. Commit

### Task 8: Typing Indicators

**Files:**
- Create: `internal/chat/typing.go`
- Create: `internal/chat/typing_test.go`

**Steps:**
1. Write failing tests for SendTyping
2. Implement SendTyping
3. Write failing tests for handleTyping
4. Implement handleTyping with auto-clear timeout
5. Write tests for timeout behavior
6. Commit

### Task 9: Stream Handling

**Files:**
- Create: `internal/chat/stream.go`
- Create: `internal/chat/stream_test.go`

**Steps:**
1. Write failing tests for writeEnvelope
2. Implement length-prefixed write
3. Write failing tests for readEnvelope
4. Implement length-prefixed read
5. Write tests for oversized envelope rejection
6. Implement readLoop
7. Commit

### Task 10: Handshake Integration

**Files:**
- Create: `internal/chat/lifecycle.go`
- Create: `internal/chat/lifecycle_test.go`

**Steps:**
1. Write failing tests for monitorHandshakeState
2. Implement state change monitoring
3. Write tests for terminal state cleanup (Unmasked, Rejected, Failed)
4. Write tests for non-terminal state survival
5. Commit

### Task 11: Agent Integration

**Files:**
- Modify: `cmd/mymonad-agent/daemon.go`
- Modify: `internal/agent/agent.go`

**Steps:**
1. Initialize ChatService in daemon
2. Register `/mymonad/chat/1.0.0` stream handler
3. Wire up IPC for chat commands
4. Commit

### Task 12: Integration Tests

**Files:**
- Create: `tests/chat_integration_test.go`

**Steps:**
1. Write full conversation test (Alice + Bob)
2. Write cleanup on unmask test
3. Write stream break test
4. Write concurrent messaging test
5. Commit

---

## 8. Security Considerations

### Cryptographic Guarantees

| Property | Mechanism |
|----------|-----------|
| Confidentiality | AES-256-GCM encryption |
| Integrity | GCM authentication tag |
| Session binding | HKDF with Session.ID as context |
| Forward secrecy | Per-session ephemeral keys (from handshake) |
| Replay protection | Random nonce per message |

### Zero Persistence

- Messages stored in RAM only
- All plaintext and keys zeroed on Cleanup()
- No disk writes, no DHT storage
- Stream closed on terminal handshake state

### Threat Mitigations

| Threat | Mitigation |
|--------|------------|
| Message tampering | GCM authentication fails |
| Replay attack | Random nonce, ACK deduplication |
| Cross-session attack | Session.ID in key derivation |
| Memory forensics | Secure zeroing on cleanup |
| Traffic analysis | libp2p transport encryption |

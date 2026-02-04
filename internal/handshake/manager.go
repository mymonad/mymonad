package handshake

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mymonad/mymonad/internal/antispam"
	"github.com/mymonad/mymonad/pkg/protocol"
)

// ManagerConfig holds configuration for the handshake manager.
type ManagerConfig struct {
	AutoInitiate     bool
	CooldownDuration time.Duration
	Threshold        float32
}

// Manager coordinates handshake sessions.
type Manager struct {
	mu          sync.RWMutex
	host        host.Host
	cfg         ManagerConfig
	sessions    map[string]*Session
	peerHistory map[peer.ID]time.Time

	// Anti-spam service for PoW-based attestation
	antiSpam *antispam.AntiSpamService

	// Event subscribers
	eventsMu    sync.RWMutex
	subscribers []chan Event
}

// Event represents a handshake event for subscribers.
type Event struct {
	SessionID      string
	EventType      string
	State          string
	PeerID         string
	ElapsedSeconds int64
}

// SessionInfo contains read-only information about a session.
// This is returned by ListSessionsInfo to avoid exposing mutable internal state.
type SessionInfo struct {
	ID              string
	PeerID          string
	Role            string
	State           string
	StartedAt       time.Time
	LastActivity    time.Time
	ElapsedSeconds  int64
	PendingApproval bool
	ApprovalType    string
}

// NewManager creates a new handshake manager.
// The host parameter may be nil for testing purposes when host features are not used.
func NewManager(h host.Host, cfg ManagerConfig) *Manager {
	return &Manager{
		host:        h,
		cfg:         cfg,
		sessions:    make(map[string]*Session),
		peerHistory: make(map[peer.ID]time.Time),
	}
}

// CanInitiate checks if we can start a handshake with the peer.
func (m *Manager) CanInitiate(peerID peer.ID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check for active session
	for _, s := range m.sessions {
		if s.PeerID == peerID && !s.Handshake.IsTerminal() {
			return false
		}
	}

	// Check cooldown
	if lastAttempt, ok := m.peerHistory[peerID]; ok {
		if time.Since(lastAttempt) < m.cfg.CooldownDuration {
			return false
		}
	}

	return true
}

// RecordAttempt records a handshake attempt time for a peer.
func (m *Manager) RecordAttempt(peerID peer.ID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerHistory[peerID] = time.Now()
}

// CreateSession creates a new session for a peer.
func (m *Manager) CreateSession(peerID peer.ID, role protocol.Role) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()

	s := NewSession(peerID, role, m.cfg.Threshold)
	m.sessions[s.ID] = s
	m.peerHistory[peerID] = time.Now()

	return s
}

// GetSession returns a session by ID.
func (m *Manager) GetSession(id string) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id]
}

// GetSessionByPeer returns an active session with a peer.
func (m *Manager) GetSessionByPeer(peerID peer.ID) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, s := range m.sessions {
		if s.PeerID == peerID && !s.Handshake.IsTerminal() {
			return s
		}
	}
	return nil
}

// RemoveSession removes a session and updates peer history.
// CRITICAL: Updates peerHistory BEFORE deletion to prevent reconnection loops.
func (m *Manager) RemoveSession(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.sessions[id]; ok {
		// Update peer history BEFORE removing
		m.peerHistory[s.PeerID] = time.Now()
		s.Cleanup()
		delete(m.sessions, id)
	}
}

// ListSessions returns all sessions.
// DEPRECATED: Use ListSessionsInfo for read-only access to avoid data races.
// This method is kept for backward compatibility but callers should not modify the returned sessions.
func (m *Manager) ListSessions() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		result = append(result, s)
	}
	return result
}

// ListSessionsInfo returns read-only information about all sessions.
// This is the preferred method for listing sessions as it returns defensive copies.
func (m *Manager) ListSessionsInfo() []SessionInfo {
	// First, copy session pointers under manager lock to avoid lock ordering issues.
	// This prevents deadlocks where another goroutine holds session lock and wants manager lock.
	m.mu.RLock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.RUnlock()

	// Now iterate over copied slice, acquiring session locks individually
	result := make([]SessionInfo, 0, len(sessions))
	for _, s := range sessions {
		s.mu.RLock()
		info := SessionInfo{
			ID:              s.ID,
			PeerID:          s.PeerID.String(),
			Role:            s.Role.String(),
			State:           s.Handshake.State().String(),
			StartedAt:       s.StartedAt,
			LastActivity:    s.LastActivity,
			ElapsedSeconds:  int64(time.Since(s.StartedAt).Seconds()),
			PendingApproval: s.PendingApproval,
			ApprovalType:    s.PendingApprovalType,
		}
		s.mu.RUnlock()
		result = append(result, info)
	}
	return result
}

// Subscribe returns a channel that receives handshake events.
func (m *Manager) Subscribe() <-chan Event {
	m.eventsMu.Lock()
	defer m.eventsMu.Unlock()

	ch := make(chan Event, 100)
	m.subscribers = append(m.subscribers, ch)
	return ch
}

// EmitEvent sends an event to all subscribers.
// Events are dropped (with warning logged) if a subscriber's channel is full.
func (m *Manager) EmitEvent(e Event) {
	m.eventsMu.RLock()
	defer m.eventsMu.RUnlock()

	for _, ch := range m.subscribers {
		select {
		case ch <- e:
		default:
			// Channel full - log warning so operators can detect subscriber backlog
			slog.Warn("dropped handshake event due to full subscriber channel",
				"session_id", e.SessionID,
				"event_type", e.EventType,
				"state", e.State,
			)
		}
	}
}

// CleanupLoop periodically removes stale sessions.
func (m *Manager) CleanupLoop(ctx context.Context, staleAfter time.Duration) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.cleanupStaleSessions(staleAfter)
		}
	}
}

func (m *Manager) cleanupStaleSessions(staleAfter time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, s := range m.sessions {
		if s.Handshake.IsTerminal() && time.Since(s.LastActivity) > staleAfter {
			m.peerHistory[s.PeerID] = time.Now()
			s.Cleanup()
			delete(m.sessions, id)
		}
	}
}

// SetAntiSpamService sets the AntiSpamService for PoW-based attestation.
// When set, the handshake protocol will use the new protobuf-based PoW
// challenge/response mechanism instead of the legacy hashcash format.
func (m *Manager) SetAntiSpamService(as *antispam.AntiSpamService) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.antiSpam = as
}

// GetAntiSpamService returns the configured AntiSpamService, or nil if not set.
func (m *Manager) GetAntiSpamService() *antispam.AntiSpamService {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.antiSpam
}

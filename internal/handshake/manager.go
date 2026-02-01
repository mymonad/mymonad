package handshake

import (
	"context"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
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

// NewManager creates a new handshake manager.
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
func (m *Manager) ListSessions() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		result = append(result, s)
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
func (m *Manager) EmitEvent(e Event) {
	m.eventsMu.RLock()
	defer m.eventsMu.RUnlock()

	for _, ch := range m.subscribers {
		select {
		case ch <- e:
		default:
			// Channel full, skip
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

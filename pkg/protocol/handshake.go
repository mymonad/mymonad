package protocol

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// State represents the current state of a handshake.
type State int

const (
	// StateIdle is the initial state before handshake begins.
	StateIdle State = iota
	// StateAttestation verifies the peer is a legitimate agent.
	StateAttestation
	// StateVectorMatch performs TEE-based embedding comparison.
	StateVectorMatch
	// StateDealBreakers exchanges yes/no questions.
	StateDealBreakers
	// StateHumanChat allows direct encrypted conversation.
	StateHumanChat
	// StateUnmask exchanges real identities.
	StateUnmask
	// StateComplete indicates successful handshake completion.
	StateComplete
	// StateFailed indicates the handshake failed.
	StateFailed
)

// String returns a human-readable name for the state.
func (s State) String() string {
	switch s {
	case StateIdle:
		return "Idle"
	case StateAttestation:
		return "Attestation"
	case StateVectorMatch:
		return "VectorMatch"
	case StateDealBreakers:
		return "DealBreakers"
	case StateHumanChat:
		return "HumanChat"
	case StateUnmask:
		return "Unmask"
	case StateComplete:
		return "Complete"
	case StateFailed:
		return "Failed"
	default:
		return fmt.Sprintf("Unknown(%d)", s)
	}
}

// Role represents whether this peer initiated or responded to the handshake.
type Role int

const (
	// RoleInitiator started the handshake.
	RoleInitiator Role = iota
	// RoleResponder received the handshake initiation.
	RoleResponder
)

// String returns a human-readable name for the role.
func (r Role) String() string {
	switch r {
	case RoleInitiator:
		return "Initiator"
	case RoleResponder:
		return "Responder"
	default:
		return fmt.Sprintf("Unknown(%d)", r)
	}
}

// Event represents an event that can trigger a state transition.
type Event int

const (
	// EventInitiate starts the handshake from Idle state.
	EventInitiate Event = iota
	// EventAttestationSuccess indicates peer attestation passed.
	EventAttestationSuccess
	// EventAttestationFailure indicates peer attestation failed.
	EventAttestationFailure
	// EventMatchAboveThreshold indicates vector similarity is sufficient.
	EventMatchAboveThreshold
	// EventMatchBelowThreshold indicates vector similarity is insufficient.
	EventMatchBelowThreshold
	// EventDealBreakersMatch indicates all deal-breaker answers matched.
	EventDealBreakersMatch
	// EventDealBreakersMismatch indicates deal-breaker mismatch.
	EventDealBreakersMismatch
	// EventChatApproval indicates human approved after chat.
	EventChatApproval
	// EventChatRejection indicates human rejected after chat.
	EventChatRejection
	// EventTimeout indicates an operation timed out.
	EventTimeout
	// EventMutualApproval indicates both parties approved unmask.
	EventMutualApproval
	// EventUnmaskRejection indicates unmask was rejected.
	EventUnmaskRejection
)

// String returns a human-readable name for the event.
func (e Event) String() string {
	switch e {
	case EventInitiate:
		return "Initiate"
	case EventAttestationSuccess:
		return "AttestationSuccess"
	case EventAttestationFailure:
		return "AttestationFailure"
	case EventMatchAboveThreshold:
		return "MatchAboveThreshold"
	case EventMatchBelowThreshold:
		return "MatchBelowThreshold"
	case EventDealBreakersMatch:
		return "DealBreakersMatch"
	case EventDealBreakersMismatch:
		return "DealBreakersMismatch"
	case EventChatApproval:
		return "ChatApproval"
	case EventChatRejection:
		return "ChatRejection"
	case EventTimeout:
		return "Timeout"
	case EventMutualApproval:
		return "MutualApproval"
	case EventUnmaskRejection:
		return "UnmaskRejection"
	default:
		return fmt.Sprintf("Unknown(%d)", e)
	}
}

// Transition errors.
var (
	ErrInvalidTransition = errors.New("invalid state transition")
	ErrTerminalState     = errors.New("cannot transition from terminal state")
)

// transition represents a valid state transition.
type transition struct {
	from  State
	event Event
	to    State
}

// validTransitions defines all allowed state transitions.
var validTransitions = []transition{
	// From Idle
	{StateIdle, EventInitiate, StateAttestation},

	// From Attestation
	{StateAttestation, EventAttestationSuccess, StateVectorMatch},
	{StateAttestation, EventAttestationFailure, StateFailed},

	// From VectorMatch
	{StateVectorMatch, EventMatchAboveThreshold, StateDealBreakers},
	{StateVectorMatch, EventMatchBelowThreshold, StateFailed},

	// From DealBreakers
	{StateDealBreakers, EventDealBreakersMatch, StateHumanChat},
	{StateDealBreakers, EventDealBreakersMismatch, StateFailed},

	// From HumanChat
	{StateHumanChat, EventChatApproval, StateUnmask},
	{StateHumanChat, EventChatRejection, StateFailed},
	{StateHumanChat, EventTimeout, StateFailed},

	// From Unmask
	{StateUnmask, EventMutualApproval, StateComplete},
	{StateUnmask, EventUnmaskRejection, StateFailed},
}

// transitionMap provides O(1) lookup for valid transitions.
var transitionMap map[State]map[Event]State

func init() {
	transitionMap = make(map[State]map[Event]State)
	for _, t := range validTransitions {
		if transitionMap[t.from] == nil {
			transitionMap[t.from] = make(map[Event]State)
		}
		transitionMap[t.from][t.event] = t.to
	}
}

// Handshake manages the state of a handshake with a peer.
type Handshake struct {
	mu        sync.RWMutex
	state     State
	role      Role
	peerID    peer.ID
	startTime time.Time
	threshold float32 // similarity threshold tau
}

// NewHandshake creates a new Handshake instance.
// The threshold is clamped to [0, 1].
func NewHandshake(role Role, peerID peer.ID, threshold float32) *Handshake {
	// Clamp threshold to valid range
	if threshold < 0 {
		threshold = 0
	}
	if threshold > 1 {
		threshold = 1
	}

	return &Handshake{
		state:     StateIdle,
		role:      role,
		peerID:    peerID,
		startTime: time.Now(),
		threshold: threshold,
	}
}

// State returns the current handshake state.
func (h *Handshake) State() State {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.state
}

// Role returns the handshake role (Initiator or Responder).
func (h *Handshake) Role() Role {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.role
}

// PeerID returns the peer's ID.
func (h *Handshake) PeerID() peer.ID {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.peerID
}

// Threshold returns the similarity threshold tau.
func (h *Handshake) Threshold() float32 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.threshold
}

// StartTime returns when the handshake started.
func (h *Handshake) StartTime() time.Time {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.startTime
}

// Duration returns how long the handshake has been running.
func (h *Handshake) Duration() time.Duration {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return time.Since(h.startTime)
}

// IsComplete returns true if the handshake completed successfully.
func (h *Handshake) IsComplete() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.state == StateComplete
}

// IsFailed returns true if the handshake failed.
func (h *Handshake) IsFailed() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.state == StateFailed
}

// IsTerminal returns true if the handshake is in a terminal state (Complete or Failed).
func (h *Handshake) IsTerminal() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.state == StateComplete || h.state == StateFailed
}

// Transition attempts to transition the handshake to a new state based on the event.
// Returns an error if the transition is not valid.
func (h *Handshake) Transition(event Event) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Check for terminal states
	if h.state == StateComplete || h.state == StateFailed {
		return fmt.Errorf("%w: current state is %s", ErrTerminalState, h.state)
	}

	// Look up valid transition
	events, ok := transitionMap[h.state]
	if !ok {
		return fmt.Errorf("%w: no transitions from state %s", ErrInvalidTransition, h.state)
	}

	nextState, ok := events[event]
	if !ok {
		return fmt.Errorf("%w: event %s not valid in state %s", ErrInvalidTransition, event, h.state)
	}

	h.state = nextState
	return nil
}

// Package chat provides encrypted chat functionality for the MyMonad protocol.
// This file implements typing indicators with auto-clear timeout functionality.
package chat

import (
	"fmt"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
)

// Typing indicator constants.
const (
	// TypingTimeout is the duration after which peer typing status is auto-cleared
	// if no further updates are received. This handles cases where the "stopped typing"
	// message was lost due to network issues.
	TypingTimeout = 5 * time.Second
)

// SendTyping sends typing status to the peer.
// When isTyping is true, it indicates the local user has started typing.
// When isTyping is false, it indicates the local user has stopped typing.
//
// Returns an error if the session is closed or the message fails to send.
func (s *ChatSession) SendTyping(isTyping bool) error {
	s.mu.RLock()
	if !s.isOpen {
		s.mu.RUnlock()
		return fmt.Errorf("chat session closed")
	}
	s.mu.RUnlock()

	envelope := &pb.ChatEnvelope{
		Payload: &pb.ChatEnvelope_Typing{
			Typing: &pb.ChatTyping{
				IsTyping: isTyping,
			},
		},
	}

	return s.writeEnvelope(envelope)
}

// handleTyping processes a received typing indicator from the peer.
// It updates the peerTyping state, calls the onTyping callback if set,
// and starts an auto-clear timer when the peer starts typing.
//
// The auto-clear mechanism ensures the typing indicator is cleared
// after TypingTimeout if no further updates are received. This handles
// network issues where the "stopped typing" message may be lost.
func (s *ChatSession) handleTyping(typing *pb.ChatTyping) {
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

// Package handshake provides attestation functions using the AntiSpamService.
package handshake

import (
	"fmt"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
	"github.com/mymonad/mymonad/pkg/hashcash"
	googleproto "google.golang.org/protobuf/proto"
)

// doNewAttestationResponder performs the responder side of attestation using AntiSpamService.
// The responder issues a PoW challenge, receives and verifies the solution.
//
// Protocol flow:
// 1. Issue PoW challenge using AntiSpamService
// 2. Send challenge to initiator
// 3. Receive solution from initiator
// 4. Verify solution using AntiSpamService
// 5. Send result (valid/invalid) to initiator
func (h *StreamHandler) doNewAttestationResponder(session *Session) error {
	// Get thread-safe copy of session stream
	stream := session.GetStream()
	peerID := session.PeerID

	// Get the AntiSpamService
	as := h.manager.GetAntiSpamService()
	if as == nil {
		return fmt.Errorf("AntiSpamService not configured")
	}

	// Issue a PoW challenge
	challenge, err := as.IssueChallenge(peerID)
	if err != nil {
		h.logger.Warn("failed to issue challenge", "peer", peerID, "error", err)
		return fmt.Errorf("failed to issue challenge: %w", err)
	}

	h.logger.Debug("issuing PoW challenge",
		"session", session.ID,
		"peer", peerID,
		"difficulty", challenge.Difficulty,
	)

	// Send challenge wrapped in HandshakeEnvelope
	challengePayload, err := googleproto.Marshal(challenge)
	if err != nil {
		return fmt.Errorf("failed to marshal challenge: %w", err)
	}

	challengeEnv := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_REQUEST,
		Payload:   challengePayload,
		Timestamp: time.Now().Unix(),
	}

	if err := WriteEnvelope(stream, challengeEnv); err != nil {
		return fmt.Errorf("failed to send challenge: %w", err)
	}

	session.UpdateActivity()

	// Read solution from initiator
	solutionEnv, err := ReadEnvelope(stream)
	if err != nil {
		return fmt.Errorf("failed to read solution: %w", err)
	}

	session.UpdateActivity()

	// Verify message type
	if solutionEnv.Type != pb.MessageType_ATTESTATION_RESPONSE {
		return fmt.Errorf("unexpected message type: %v", solutionEnv.Type)
	}

	// Parse solution
	var solution pb.PoWSolution
	if err := googleproto.Unmarshal(solutionEnv.Payload, &solution); err != nil {
		return fmt.Errorf("failed to unmarshal solution: %w", err)
	}

	h.logger.Debug("received PoW solution",
		"session", session.ID,
		"counter", solution.Counter,
	)

	// Verify the solution using AntiSpamService
	verifyErr := as.VerifyResponse(challenge, &solution, peerID)

	// Send result to initiator
	var result *pb.PoWResult
	if verifyErr != nil {
		h.logger.Debug("PoW verification failed",
			"session", session.ID,
			"error", verifyErr,
		)
		result = &pb.PoWResult{
			Valid: false,
			Error: verifyErr.Error(),
		}
	} else {
		h.logger.Debug("PoW verification succeeded",
			"session", session.ID,
		)
		result = &pb.PoWResult{
			Valid: true,
		}
	}

	resultPayload, err := googleproto.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	resultEnv := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_RESPONSE,
		Payload:   resultPayload,
		Timestamp: time.Now().Unix(),
	}

	if err := WriteEnvelope(stream, resultEnv); err != nil {
		return fmt.Errorf("failed to send result: %w", err)
	}

	session.UpdateActivity()

	// If verification failed, return error
	if verifyErr != nil {
		return fmt.Errorf("verification failed: %w", verifyErr)
	}

	return nil
}

// doNewAttestationInitiator performs the initiator side of attestation.
// The initiator receives a PoW challenge, mines a solution, and sends it.
//
// Protocol flow:
// 1. Receive PoW challenge from responder
// 2. Mine solution using Miner
// 3. Send solution to responder
// 4. Receive result from responder
func (h *StreamHandler) doNewAttestationInitiator(session *Session) error {
	// Get thread-safe copy of session stream
	stream := session.GetStream()

	// Get our peer ID (for mining)
	// The miner needs the prover's peer ID to compute the hash correctly.
	var myPeerID []byte
	if h.manager.host != nil {
		myPeerID = []byte(h.manager.host.ID())
	}
	// Note: myPeerID may be nil here; we'll use the challenge's PeerId if needed

	// Read challenge from responder
	challengeEnv, err := ReadEnvelope(stream)
	if err != nil {
		return fmt.Errorf("failed to read challenge: %w", err)
	}

	session.UpdateActivity()

	// Verify message type
	if challengeEnv.Type != pb.MessageType_ATTESTATION_REQUEST {
		return fmt.Errorf("unexpected message type: %v", challengeEnv.Type)
	}

	// Parse challenge
	var challenge pb.PoWChallenge
	if err := googleproto.Unmarshal(challengeEnv.Payload, &challenge); err != nil {
		return fmt.Errorf("failed to unmarshal challenge: %w", err)
	}

	h.logger.Info("received PoW challenge",
		"session", session.ID,
		"peer", session.PeerID,
		"difficulty", challenge.Difficulty,
	)

	// Determine the peer ID to use for mining.
	// In normal operation, we use our host's peer ID.
	// If the host is nil (testing), we use the PeerId from the challenge
	// (which the responder set to our expected peer ID).
	proverID := myPeerID
	if proverID == nil {
		// Use the peer ID from the challenge for testing scenarios
		proverID = challenge.PeerId
	}

	// Mine solution
	miner := hashcash.NewMiner(0) // 0 = use default max iterations
	result, err := miner.Mine(&challenge, proverID)
	if err != nil {
		return fmt.Errorf("mining failed: %w", err)
	}

	h.logger.Debug("mined PoW solution",
		"session", session.ID,
		"counter", result.Counter,
		"elapsed", result.Elapsed,
	)

	// Create solution
	solution := &pb.PoWSolution{
		ChallengeNonce:     challenge.Nonce,
		ChallengeTimestamp: challenge.Timestamp,
		Counter:            result.Counter,
		Proof:              result.Proof,
	}

	// Send solution
	solutionPayload, err := googleproto.Marshal(solution)
	if err != nil {
		return fmt.Errorf("failed to marshal solution: %w", err)
	}

	solutionEnv := &pb.HandshakeEnvelope{
		Type:      pb.MessageType_ATTESTATION_RESPONSE,
		Payload:   solutionPayload,
		Timestamp: time.Now().Unix(),
	}

	if err := WriteEnvelope(stream, solutionEnv); err != nil {
		return fmt.Errorf("failed to send solution: %w", err)
	}

	session.UpdateActivity()

	// Read result from responder
	resultEnv, err := ReadEnvelope(stream)
	if err != nil {
		return fmt.Errorf("failed to read result: %w", err)
	}

	session.UpdateActivity()

	// Verify message type (can be ATTESTATION_RESPONSE or REJECT)
	if resultEnv.Type == pb.MessageType_REJECT {
		var rejectPayload pb.RejectPayload
		if err := googleproto.Unmarshal(resultEnv.Payload, &rejectPayload); err != nil {
			return fmt.Errorf("peer rejected (unable to parse reason)")
		}
		return fmt.Errorf("peer rejected: %s", rejectPayload.Reason)
	}

	if resultEnv.Type != pb.MessageType_ATTESTATION_RESPONSE {
		return fmt.Errorf("unexpected message type: %v", resultEnv.Type)
	}

	// Parse result
	var powResult pb.PoWResult
	if err := googleproto.Unmarshal(resultEnv.Payload, &powResult); err != nil {
		return fmt.Errorf("failed to unmarshal result: %w", err)
	}

	// Check result
	if !powResult.Valid {
		return fmt.Errorf("PoW rejected: %s", powResult.Error)
	}

	h.logger.Info("PoW attestation succeeded",
		"session", session.ID,
	)

	return nil
}

// UseNewAttestation returns true if the new AntiSpamService-based attestation
// should be used instead of the legacy hashcash attestation.
func (h *StreamHandler) UseNewAttestation() bool {
	return h.manager.GetAntiSpamService() != nil
}

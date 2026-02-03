// Package hashcash provides Proof-of-Work mining and verification for anti-spam.
//
// This file implements the verification functionality for validating PoW solutions.
// It verifies that a miner's solution is valid for a given challenge.
package hashcash

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/mymonad/mymonad/api/proto"
)

// Verification errors returned by Verify.
// Note: ErrNilChallenge is defined in hashcash.go and reused here.
var (
	// ErrNilSolution is returned when the solution is nil.
	ErrNilSolution = errors.New("nil solution")

	// ErrNonceMismatch is returned when solution.ChallengeNonce does not match challenge.Nonce.
	ErrNonceMismatch = errors.New("nonce mismatch")

	// ErrTimestampMismatch is returned when solution.ChallengeTimestamp does not match challenge.Timestamp.
	ErrTimestampMismatch = errors.New("timestamp mismatch")

	// ErrHashMismatch is returned when the recomputed hash does not match solution.Proof.
	ErrHashMismatch = errors.New("hash mismatch")

	// ErrInsufficientDifficulty is returned when the hash does not meet the required difficulty.
	ErrInsufficientDifficulty = errors.New("insufficient difficulty")
)

// Verify validates a PoW solution against the original challenge.
//
// The verification process checks (in order):
//  1. Neither challenge nor solution is nil
//  2. Solution's challenge nonce matches the original challenge nonce
//  3. Solution's challenge timestamp matches the original challenge timestamp
//  4. Recomputed hash matches the solution's proof
//  5. The hash meets the required difficulty target
//
// The hash is computed as: SHA-256(nonce || timestamp || proverPeerID || counter)
// where || denotes concatenation and timestamp/counter are in big-endian binary format.
//
// Returns nil if the solution is valid, or an error describing the validation failure.
func Verify(challenge *proto.PoWChallenge, solution *proto.PoWSolution, proverPeerID []byte) error {
	// Check for nil inputs
	if challenge == nil {
		return ErrNilChallenge
	}
	if solution == nil {
		return ErrNilSolution
	}

	// Check nonce matches
	if !bytes.Equal(challenge.Nonce, solution.ChallengeNonce) {
		return ErrNonceMismatch
	}

	// Check timestamp matches
	if challenge.Timestamp != solution.ChallengeTimestamp {
		return ErrTimestampMismatch
	}

	// Recompute the hash
	prefix := buildPrefix(challenge.Nonce, challenge.Timestamp, proverPeerID)
	counterBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBuf, solution.Counter)

	hash := sha256.Sum256(append(prefix, counterBuf...))

	// Verify proof matches
	if !bytes.Equal(hash[:], solution.Proof) {
		return ErrHashMismatch
	}

	// Verify difficulty
	target := difficultyTarget(challenge.Difficulty)
	if !meetsTarget(hash[:], target) {
		return ErrInsufficientDifficulty
	}

	return nil
}

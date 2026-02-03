// Package hashcash provides Proof-of-Work mining and verification for anti-spam.
//
// This file implements the mining functionality for the protobuf-based PoW system.
// It works with PoWChallenge messages and produces PoWSolution-compatible results.
package hashcash

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/mymonad/mymonad/api/proto"
)

// DefaultMaxIterations is the maximum number of mining attempts before giving up.
// 2^32 iterations should be sufficient for any reasonable difficulty.
const DefaultMaxIterations = uint64(1 << 32)

// Miner performs proof-of-work mining for PoW challenges.
// It finds a counter value that produces a hash with the required leading zeros.
type Miner struct {
	maxIterations uint64
}

// MineResult contains the result of a successful mining operation.
type MineResult struct {
	// Counter is the nonce value that produces a valid hash.
	Counter uint64

	// Proof is the SHA-256 hash that has the required leading zeros.
	Proof []byte

	// Elapsed is the time spent mining.
	Elapsed time.Duration
}

// NewMiner creates a new Miner with the specified maximum iterations.
// If maxIterations is 0, DefaultMaxIterations is used.
func NewMiner(maxIterations uint64) *Miner {
	if maxIterations == 0 {
		maxIterations = DefaultMaxIterations
	}
	return &Miner{
		maxIterations: maxIterations,
	}
}

// Mine finds a counter value that produces a hash with the required leading zeros.
//
// The hash is computed as: SHA-256(nonce || timestamp || localPeerID || counter)
// where || denotes concatenation and all values are in big-endian binary format.
//
// Returns a MineResult containing the counter, proof hash, and elapsed time.
// Returns an error if no solution is found within maxIterations attempts.
func (m *Miner) Mine(challenge *proto.PoWChallenge, localPeerID []byte) (*MineResult, error) {
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

// buildPrefix constructs the prefix portion of the hash input.
// The prefix is: nonce || timestamp (big-endian uint64) || peerID
func buildPrefix(nonce []byte, timestamp int64, peerID []byte) []byte {
	buf := make([]byte, len(nonce)+8+len(peerID))
	copy(buf, nonce)
	binary.BigEndian.PutUint64(buf[len(nonce):], uint64(timestamp))
	copy(buf[len(nonce)+8:], peerID)
	return buf
}

// difficultyTarget creates a 32-byte target value for the specified difficulty.
//
// The difficulty is the number of required leading zero bits. The target is set
// such that any hash strictly less than the target has at least that many zeros.
//
// For example:
//   - 16 bits: target[2] = 0x80, so hashes must be < 0x0000800000...
//   - 20 bits: target[2] = 0x08, so hashes must be < 0x0000080000...
//   - 24 bits: target[3] = 0x80, so hashes must be < 0x0000008000...
func difficultyTarget(bits uint32) []byte {
	target := make([]byte, 32)
	byteIndex := bits / 8
	bitOffset := bits % 8

	if byteIndex < 32 {
		target[byteIndex] = 0x80 >> bitOffset
	}

	return target
}

// meetsTarget checks if a hash is strictly less than the target.
// This is equivalent to having at least the required number of leading zero bits.
func meetsTarget(hash, target []byte) bool {
	return bytes.Compare(hash, target) < 0
}

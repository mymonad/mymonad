// Package zkproof provides zero-knowledge proof exchange functionality.
//
// ZKExchange implements the protocol for exchanging ZK proofs between peers.
// The exchange protocol ensures mutual privacy: both peers prove knowledge of
// signatures within the agreed Hamming distance without revealing the actual
// signatures.
//
// # Protocol Flow (Initiator)
//
//  1. Generate proof of our signature's proximity to peer's signature
//  2. Send ZKProofRequest with our commitment and signature
//  3. Receive peer's ZKProofResponse with their proof
//  4. Verify peer's proof
//  5. Send our ZKProofResponse with our proof
//  6. Receive verification result
//
// # Protocol Flow (Responder)
//
//  1. Receive ZKProofRequest
//  2. Generate proof of our signature's proximity to peer's signature
//  3. Send ZKProofResponse with our proof
//  4. Receive peer's ZKProofResponse
//  5. Verify peer's proof
//  6. Send verification result
//
// # Thread Safety
//
// ZKExchange is safe for concurrent use from multiple goroutines.
// Each exchange operates on its own stream and does not share mutable state.
package zkproof

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
	"google.golang.org/protobuf/proto"
)

// ZKProtocolID is the libp2p protocol identifier for ZK proof exchanges.
const ZKProtocolID = "/mymonad/zkproof/1.0.0"

// ZKMaxPayloadSize is the maximum allowed payload size (16 MB).
// This prevents memory exhaustion attacks from malicious peers.
// ZK proofs are typically a few KB, so this provides ample headroom.
const ZKMaxPayloadSize = 16 * 1024 * 1024

// ZKMessageType identifies the type of ZK protocol message.
type ZKMessageType uint8

const (
	// ZKMessageTypeRequest indicates a ZKProofRequest message.
	ZKMessageTypeRequest ZKMessageType = iota
	// ZKMessageTypeResponse indicates a ZKProofResponse message.
	ZKMessageTypeResponse
	// ZKMessageTypeResult indicates a ZKProofResult message.
	ZKMessageTypeResult
)

// ZK protocol errors.
var (
	// ErrZKNilMessage is returned when attempting to write a nil message.
	ErrZKNilMessage = errors.New("zkproof: message cannot be nil")
	// ErrZKPayloadTooLarge is returned when payload exceeds ZKMaxPayloadSize.
	ErrZKPayloadTooLarge = errors.New("zkproof: payload exceeds maximum size")
	// ErrZKUnexpectedMessageType is returned when message type doesn't match expected.
	ErrZKUnexpectedMessageType = errors.New("zkproof: unexpected message type")
)

// ProofResult contains the result of proof generation.
// This is a simplified interface-compatible version of zkproof.ProofResult.
type ProofResult struct {
	// Proof is the serialized zero-knowledge proof.
	Proof []byte
	// Commitment is the MiMC hash of the prover's signature.
	Commitment []byte
}

// ProverInterface defines the interface for proof generation.
// This allows testing with mock implementations.
type ProverInterface interface {
	GenerateProof(mySignature, peerSignature []byte, maxDistance uint32) (*ProofResult, error)
}

// VerifierInterface defines the interface for proof verification.
// This allows testing with mock implementations.
type VerifierInterface interface {
	VerifyProof(proofBytes, proverCommitment, peerSignature []byte, maxDistance uint32) error
}

// StreamReadWriter combines read and write operations for a network stream.
type StreamReadWriter interface {
	io.Reader
	io.Writer
	SetReadDeadline(t time.Time) error
}

// ZKExchange handles zero-knowledge proof exchanges between peers.
// It orchestrates the generation and verification of proofs to establish
// that both peers have signatures within the agreed Hamming distance.
type ZKExchange struct {
	prover   ProverInterface
	verifier VerifierInterface
	config   ZKConfig
}

// NewZKExchange creates a new ZKExchange with the given prover, verifier, and config.
//
// The prover is used to generate proofs of our signature's proximity.
// The verifier is used to verify proofs from the peer.
// The config provides exchange parameters like timeout and max distance.
func NewZKExchange(prover ProverInterface, verifier VerifierInterface, config ZKConfig) *ZKExchange {
	return &ZKExchange{
		prover:   prover,
		verifier: verifier,
		config:   config,
	}
}

// InitiateExchange starts a ZK proof exchange with a peer.
//
// This method is called by the initiator (the peer that discovered the other).
// It performs the full exchange protocol:
//  1. Generate our proof
//  2. Send request with our commitment and signature
//  3. Receive peer's proof and verify it
//  4. Send our proof
//  5. Receive verification result
//
// Parameters:
//   - ctx: Context for cancellation (currently used for deadline signaling)
//   - stream: The bidirectional stream to the peer
//   - mySignature: Our 32-byte LSH signature
//   - peerSignature: The peer's 32-byte LSH signature
//
// Returns nil on successful exchange, or an error describing the failure.
func (zk *ZKExchange) InitiateExchange(
	ctx context.Context,
	stream StreamReadWriter,
	mySignature []byte,
	peerSignature []byte,
) error {
	// 1. Generate our proof
	proofResult, err := zk.prover.GenerateProof(mySignature, peerSignature, zk.config.MaxDistance)
	if err != nil {
		return fmt.Errorf("generate proof: %w", err)
	}

	// 2. Send request with our commitment and signature
	request := &pb.ZKProofRequest{
		MaxDistance: zk.config.MaxDistance,
		Commitment:  proofResult.Commitment,
		Signature:   mySignature,
	}
	if err := writeZKRequest(stream, request); err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	// 3. Receive peer's response
	if err := stream.SetReadDeadline(time.Now().Add(zk.config.ProofTimeout)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	response, err := readZKResponse(stream)
	if err != nil {
		return fmt.Errorf("receive response: %w", err)
	}

	// 4. Verify peer's proof against our signature
	if err := zk.verifier.VerifyProof(
		response.Proof,
		response.Commitment,
		mySignature,
		zk.config.MaxDistance,
	); err != nil {
		// Send rejection before returning error (log if send fails)
		if sendErr := sendZKResult(stream, &pb.ZKProofResult{Valid: false, Error: err.Error()}); sendErr != nil {
			slog.Warn("failed to send ZK rejection result", "error", sendErr)
		}
		return fmt.Errorf("peer proof invalid: %w", err)
	}

	// 5. Send our proof
	myResponse := &pb.ZKProofResponse{
		Proof:      proofResult.Proof,
		Commitment: proofResult.Commitment,
		Signature:  mySignature,
	}
	if err := writeZKResponse(stream, myResponse); err != nil {
		return fmt.Errorf("send response: %w", err)
	}

	// 6. Receive verification result
	result, err := readZKResult(stream)
	if err != nil {
		return fmt.Errorf("receive result: %w", err)
	}

	if !result.Valid {
		return fmt.Errorf("our proof rejected: %s", result.Error)
	}

	return nil
}

// HandleExchange responds to a ZK proof exchange request from a peer.
//
// This method is called by the responder (the peer that received the request).
// It performs the responder side of the exchange protocol:
//  1. Receive request
//  2. Generate our proof
//  3. Send our response with proof
//  4. Receive peer's proof and verify it
//  5. Send verification result
//
// Parameters:
//   - ctx: Context for cancellation (currently used for deadline signaling)
//   - stream: The bidirectional stream from the initiator
//   - mySignature: Our 32-byte LSH signature
//
// Returns nil on successful exchange, or an error describing the failure.
func (zk *ZKExchange) HandleExchange(
	ctx context.Context,
	stream StreamReadWriter,
	mySignature []byte,
) error {
	// 1. Receive request
	if err := stream.SetReadDeadline(time.Now().Add(zk.config.ProofTimeout)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	request, err := readZKRequest(stream)
	if err != nil {
		return fmt.Errorf("receive request: %w", err)
	}

	// 2. Generate our proof against peer's signature
	proofResult, err := zk.prover.GenerateProof(mySignature, request.Signature, request.MaxDistance)
	if err != nil {
		return fmt.Errorf("generate proof: %w", err)
	}

	// 3. Send our response
	response := &pb.ZKProofResponse{
		Proof:      proofResult.Proof,
		Commitment: proofResult.Commitment,
		Signature:  mySignature,
	}
	if err := writeZKResponse(stream, response); err != nil {
		return fmt.Errorf("send response: %w", err)
	}

	// 4. Receive peer's proof
	peerResponse, err := readZKResponse(stream)
	if err != nil {
		return fmt.Errorf("receive peer proof: %w", err)
	}

	// 5. Verify peer's proof against our signature
	if err := zk.verifier.VerifyProof(
		peerResponse.Proof,
		request.Commitment, // Use the commitment from the original request
		mySignature,
		request.MaxDistance,
	); err != nil {
		// Send rejection before returning error (log if send fails)
		if sendErr := sendZKResult(stream, &pb.ZKProofResult{Valid: false, Error: err.Error()}); sendErr != nil {
			slog.Warn("failed to send ZK rejection result", "error", sendErr)
		}
		return fmt.Errorf("peer proof invalid: %w", err)
	}

	// 6. Send success
	return sendZKResult(stream, &pb.ZKProofResult{Valid: true})
}

// writeZKMessage writes a ZK protocol message to a writer.
// Format: [type:1 byte][length:4 bytes BE][payload]
func writeZKMessage(w io.Writer, msgType ZKMessageType, payload []byte) error {
	// Write message type (1 byte)
	if _, err := w.Write([]byte{byte(msgType)}); err != nil {
		return fmt.Errorf("write type: %w", err)
	}

	// Write payload length (4 bytes big-endian)
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(payload)))
	if _, err := w.Write(lenBuf); err != nil {
		return fmt.Errorf("write length: %w", err)
	}

	// Write payload
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	}

	return nil
}

// readZKMessage reads a ZK protocol message from a reader.
// Returns the message type and payload, or an error.
func readZKMessage(r io.Reader) (ZKMessageType, []byte, error) {
	// Read message type (1 byte)
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, typeBuf); err != nil {
		if err == io.EOF {
			return 0, nil, io.EOF
		}
		return 0, nil, fmt.Errorf("read type: %w", err)
	}

	// Read payload length (4 bytes big-endian)
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return 0, nil, fmt.Errorf("read length: %w", err)
	}
	payloadLen := binary.BigEndian.Uint32(lenBuf)

	// Validate payload size
	if payloadLen > ZKMaxPayloadSize {
		return 0, nil, fmt.Errorf("%w: %d bytes", ErrZKPayloadTooLarge, payloadLen)
	}

	// Read payload
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, fmt.Errorf("read payload: %w", err)
		}
	}

	return ZKMessageType(typeBuf[0]), payload, nil
}

// writeZKRequest writes a ZKProofRequest to a writer.
func writeZKRequest(w io.Writer, req *pb.ZKProofRequest) error {
	if req == nil {
		return ErrZKNilMessage
	}

	payload, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	return writeZKMessage(w, ZKMessageTypeRequest, payload)
}

// readZKRequest reads a ZKProofRequest from a reader.
// Returns an error if the message type is not ZKMessageTypeRequest.
func readZKRequest(r io.Reader) (*pb.ZKProofRequest, error) {
	msgType, payload, err := readZKMessage(r)
	if err != nil {
		return nil, err
	}

	if msgType != ZKMessageTypeRequest {
		return nil, fmt.Errorf("%w: got %d, want %d",
			ErrZKUnexpectedMessageType, msgType, ZKMessageTypeRequest)
	}

	req := &pb.ZKProofRequest{}
	if err := proto.Unmarshal(payload, req); err != nil {
		return nil, fmt.Errorf("unmarshal request: %w", err)
	}

	return req, nil
}

// writeZKResponse writes a ZKProofResponse to a writer.
func writeZKResponse(w io.Writer, resp *pb.ZKProofResponse) error {
	if resp == nil {
		return ErrZKNilMessage
	}

	payload, err := proto.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal response: %w", err)
	}

	return writeZKMessage(w, ZKMessageTypeResponse, payload)
}

// readZKResponse reads a ZKProofResponse from a reader.
// Returns an error if the message type is not ZKMessageTypeResponse.
func readZKResponse(r io.Reader) (*pb.ZKProofResponse, error) {
	msgType, payload, err := readZKMessage(r)
	if err != nil {
		return nil, err
	}

	if msgType != ZKMessageTypeResponse {
		return nil, fmt.Errorf("%w: got %d, want %d",
			ErrZKUnexpectedMessageType, msgType, ZKMessageTypeResponse)
	}

	resp := &pb.ZKProofResponse{}
	if err := proto.Unmarshal(payload, resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return resp, nil
}

// writeZKResult writes a ZKProofResult to a writer.
func writeZKResult(w io.Writer, result *pb.ZKProofResult) error {
	if result == nil {
		return ErrZKNilMessage
	}

	payload, err := proto.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}

	return writeZKMessage(w, ZKMessageTypeResult, payload)
}

// readZKResult reads a ZKProofResult from a reader.
// Returns an error if the message type is not ZKMessageTypeResult.
func readZKResult(r io.Reader) (*pb.ZKProofResult, error) {
	msgType, payload, err := readZKMessage(r)
	if err != nil {
		return nil, err
	}

	if msgType != ZKMessageTypeResult {
		return nil, fmt.Errorf("%w: got %d, want %d",
			ErrZKUnexpectedMessageType, msgType, ZKMessageTypeResult)
	}

	result := &pb.ZKProofResult{}
	if err := proto.Unmarshal(payload, result); err != nil {
		return nil, fmt.Errorf("unmarshal result: %w", err)
	}

	return result, nil
}

// sendZKResult is a convenience function that writes a ZKProofResult
// and ignores the error (used for best-effort result sending).
func sendZKResult(w io.Writer, result *pb.ZKProofResult) error {
	return writeZKResult(w, result)
}

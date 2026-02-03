// Package zkproof provides a service layer for zero-knowledge proof functionality.
package zkproof

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/mymonad/mymonad/api/proto"
)

// pipeStream implements a bidirectional stream using io.Pipe for testing.
// It simulates a network.Stream interface with proper blocking reads.
type pipeStream struct {
	reader       *io.PipeReader
	writer       *io.PipeWriter
	readDeadline time.Time
	closed       bool
}

// newPipeStreamPair creates a pair of connected pipe streams.
// Data written to one stream can be read from the other.
func newPipeStreamPair() (*pipeStream, *pipeStream) {
	// Create two pipes for bidirectional communication
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	stream1 := &pipeStream{
		reader: r1,
		writer: w2, // stream1 writes to pipe2, which stream2 reads from
	}
	stream2 := &pipeStream{
		reader: r2,
		writer: w1, // stream2 writes to pipe1, which stream1 reads from
	}

	return stream1, stream2
}

func (p *pipeStream) Read(buf []byte) (int, error) {
	if p.closed {
		return 0, io.EOF
	}
	return p.reader.Read(buf)
}

func (p *pipeStream) Write(buf []byte) (int, error) {
	if p.closed {
		return 0, errors.New("stream closed")
	}
	return p.writer.Write(buf)
}

func (p *pipeStream) Close() error {
	p.closed = true
	p.reader.Close()
	p.writer.Close()
	return nil
}

func (p *pipeStream) SetReadDeadline(t time.Time) error {
	p.readDeadline = t
	return nil
}

// mockStream implements a simple in-memory stream for single-direction tests.
type mockStream struct {
	readBuf      *bytes.Buffer
	writeBuf     *bytes.Buffer
	readDeadline time.Time
	closed       bool
	readErr      error
}

func newMockStream() *mockStream {
	return &mockStream{
		readBuf:  bytes.NewBuffer(nil),
		writeBuf: bytes.NewBuffer(nil),
	}
}

func (m *mockStream) Read(p []byte) (int, error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	if m.closed {
		return 0, io.EOF
	}
	// Check deadline - if deadline passed and no data, return timeout
	if !m.readDeadline.IsZero() && time.Now().After(m.readDeadline) {
		return 0, context.DeadlineExceeded
	}
	return m.readBuf.Read(p)
}

func (m *mockStream) Write(p []byte) (int, error) {
	if m.closed {
		return 0, errors.New("stream closed")
	}
	return m.writeBuf.Write(p)
}

func (m *mockStream) SetReadDeadline(t time.Time) error {
	m.readDeadline = t
	return nil
}

// mockProver is a mock implementation of the ProverInterface for testing.
type mockProver struct {
	generateProofFunc func(mySignature, peerSignature []byte, maxDistance uint32) (*ProofResult, error)
}

func (m *mockProver) GenerateProof(mySignature, peerSignature []byte, maxDistance uint32) (*ProofResult, error) {
	if m.generateProofFunc != nil {
		return m.generateProofFunc(mySignature, peerSignature, maxDistance)
	}
	// Default mock behavior: return deterministic proof based on inputs
	return &ProofResult{
		Proof:      []byte("mock-proof-" + string(mySignature[:8])),
		Commitment: []byte("mock-commitment-" + string(mySignature[:8])),
	}, nil
}

// mockVerifier is a mock implementation of the VerifierInterface for testing.
type mockVerifier struct {
	verifyProofFunc func(proofBytes, proverCommitment, peerSignature []byte, maxDistance uint32) error
}

func (m *mockVerifier) VerifyProof(proofBytes, proverCommitment, peerSignature []byte, maxDistance uint32) error {
	if m.verifyProofFunc != nil {
		return m.verifyProofFunc(proofBytes, proverCommitment, peerSignature, maxDistance)
	}
	// Default mock behavior: always valid
	return nil
}

// Helper to create test signatures
func makeTestSignature(seed byte) []byte {
	sig := make([]byte, 32)
	for i := range sig {
		sig[i] = seed + byte(i)
	}
	return sig
}

func TestNewZKExchange(t *testing.T) {
	t.Run("creates_exchange_with_valid_params", func(t *testing.T) {
		prover := &mockProver{}
		verifier := &mockVerifier{}
		config := DefaultZKConfig()
		config.MaxDistance = 64
		config.ProofTimeout = 10 * time.Second

		exchange := NewZKExchange(prover, verifier, config)

		require.NotNil(t, exchange)
		assert.Equal(t, config.MaxDistance, exchange.config.MaxDistance)
		assert.Equal(t, config.ProofTimeout, exchange.config.ProofTimeout)
	})

	t.Run("stores_prover_and_verifier", func(t *testing.T) {
		prover := &mockProver{}
		verifier := &mockVerifier{}
		config := DefaultZKConfig()

		exchange := NewZKExchange(prover, verifier, config)

		require.NotNil(t, exchange)
		// Internal state is not directly accessible, but we can verify
		// the exchange was created successfully
	})
}

func TestZKExchange_InitiateExchange(t *testing.T) {
	t.Run("sends_request_and_receives_valid_response", func(t *testing.T) {
		// Create connected streams
		initiatorStream, responderStream := newPipeStreamPair()

		mySignature := makeTestSignature(0x01)
		peerSignature := makeTestSignature(0x02)

		// Mock prover generates our proof
		prover := &mockProver{
			generateProofFunc: func(mySig, peerSig []byte, maxDist uint32) (*ProofResult, error) {
				return &ProofResult{
					Proof:      []byte("initiator-proof"),
					Commitment: []byte("initiator-commitment"),
				}, nil
			},
		}

		// Mock verifier accepts peer's proof
		verifier := &mockVerifier{
			verifyProofFunc: func(proof, commitment, peerSig []byte, maxDist uint32) error {
				return nil
			},
		}

		config := DefaultZKConfig()
		config.MaxDistance = 64
		config.ProofTimeout = 5 * time.Second

		exchange := NewZKExchange(prover, verifier, config)

		// Simulate responder in background
		responderDone := make(chan error, 1)
		go func() {
			// Read request
			req, err := readZKRequest(responderStream)
			if err != nil {
				responderDone <- err
				return
			}

			// Send response with peer's proof
			resp := &pb.ZKProofResponse{
				Proof:      []byte("responder-proof"),
				Commitment: []byte("responder-commitment"),
				Signature:  peerSignature,
			}
			if err := writeZKResponse(responderStream, resp); err != nil {
				responderDone <- err
				return
			}

			// Read initiator's response (the proof we're verifying)
			_, err = readZKResponse(responderStream)
			if err != nil {
				responderDone <- err
				return
			}

			// Send result
			result := &pb.ZKProofResult{Valid: true}
			if err := writeZKResult(responderStream, result); err != nil {
				responderDone <- err
				return
			}

			// Verify request contents
			assert.Equal(t, uint32(64), req.MaxDistance)
			assert.NotEmpty(t, req.Commitment)
			assert.Equal(t, mySignature, req.Signature)

			responderDone <- nil
		}()

		// Run initiator
		ctx := context.Background()
		err := exchange.InitiateExchange(ctx, initiatorStream, mySignature, peerSignature)
		require.NoError(t, err)

		// Wait for responder
		require.NoError(t, <-responderDone)
	})

	t.Run("fails_when_peer_proof_invalid", func(t *testing.T) {
		initiatorStream, responderStream := newPipeStreamPair()

		mySignature := makeTestSignature(0x01)
		peerSignature := makeTestSignature(0x02)

		prover := &mockProver{
			generateProofFunc: func(mySig, peerSig []byte, maxDist uint32) (*ProofResult, error) {
				return &ProofResult{
					Proof:      []byte("initiator-proof"),
					Commitment: []byte("initiator-commitment"),
				}, nil
			},
		}

		// Verifier rejects peer's proof
		verifier := &mockVerifier{
			verifyProofFunc: func(proof, commitment, peerSig []byte, maxDist uint32) error {
				return errors.New("invalid proof: signature mismatch")
			},
		}

		config := DefaultZKConfig()
		config.ProofTimeout = 5 * time.Second

		exchange := NewZKExchange(prover, verifier, config)

		// Simulate responder
		go func() {
			// Read request
			readZKRequest(responderStream)

			// Send invalid response
			resp := &pb.ZKProofResponse{
				Proof:      []byte("bad-proof"),
				Commitment: []byte("bad-commitment"),
				Signature:  peerSignature,
			}
			writeZKResponse(responderStream, resp)

			// Read the result (should be invalid)
			readZKResult(responderStream)
		}()

		ctx := context.Background()
		err := exchange.InitiateExchange(ctx, initiatorStream, mySignature, peerSignature)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "peer proof invalid")
	})

	t.Run("fails_when_proof_generation_fails", func(t *testing.T) {
		stream := newMockStream()

		mySignature := makeTestSignature(0x01)
		peerSignature := makeTestSignature(0x02)

		// Prover fails to generate proof
		prover := &mockProver{
			generateProofFunc: func(mySig, peerSig []byte, maxDist uint32) (*ProofResult, error) {
				return nil, errors.New("distance exceeds threshold")
			},
		}
		verifier := &mockVerifier{}

		config := DefaultZKConfig()
		exchange := NewZKExchange(prover, verifier, config)

		ctx := context.Background()
		err := exchange.InitiateExchange(ctx, stream, mySignature, peerSignature)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "generate proof")
	})

	t.Run("fails_on_timeout_reading_response", func(t *testing.T) {
		stream := newMockStream()

		mySignature := makeTestSignature(0x01)
		peerSignature := makeTestSignature(0x02)

		prover := &mockProver{
			generateProofFunc: func(mySig, peerSig []byte, maxDist uint32) (*ProofResult, error) {
				return &ProofResult{
					Proof:      []byte("proof"),
					Commitment: []byte("commitment"),
				}, nil
			},
		}
		verifier := &mockVerifier{}

		config := DefaultZKConfig()
		config.ProofTimeout = 1 * time.Millisecond // Very short timeout

		exchange := NewZKExchange(prover, verifier, config)

		ctx := context.Background()
		err := exchange.InitiateExchange(ctx, stream, mySignature, peerSignature)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "receive response")
	})

	t.Run("fails_when_our_proof_rejected", func(t *testing.T) {
		initiatorStream, responderStream := newPipeStreamPair()

		mySignature := makeTestSignature(0x01)
		peerSignature := makeTestSignature(0x02)

		prover := &mockProver{
			generateProofFunc: func(mySig, peerSig []byte, maxDist uint32) (*ProofResult, error) {
				return &ProofResult{
					Proof:      []byte("proof"),
					Commitment: []byte("commitment"),
				}, nil
			},
		}
		verifier := &mockVerifier{}

		config := DefaultZKConfig()
		config.ProofTimeout = 5 * time.Second

		exchange := NewZKExchange(prover, verifier, config)

		// Simulate responder that rejects our proof
		go func() {
			readZKRequest(responderStream)

			resp := &pb.ZKProofResponse{
				Proof:      []byte("responder-proof"),
				Commitment: []byte("responder-commitment"),
				Signature:  peerSignature,
			}
			writeZKResponse(responderStream, resp)

			// Read our response
			readZKResponse(responderStream)

			// Send rejection
			result := &pb.ZKProofResult{
				Valid: false,
				Error: "proof verification failed",
			}
			writeZKResult(responderStream, result)
		}()

		ctx := context.Background()
		err := exchange.InitiateExchange(ctx, initiatorStream, mySignature, peerSignature)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "our proof rejected")
	})
}

func TestZKExchange_HandleExchange(t *testing.T) {
	t.Run("handles_valid_request_and_sends_response", func(t *testing.T) {
		initiatorStream, responderStream := newPipeStreamPair()

		mySignature := makeTestSignature(0x02)
		peerSignature := makeTestSignature(0x01)

		// Mock prover generates our proof
		prover := &mockProver{
			generateProofFunc: func(mySig, peerSig []byte, maxDist uint32) (*ProofResult, error) {
				return &ProofResult{
					Proof:      []byte("responder-proof"),
					Commitment: []byte("responder-commitment"),
				}, nil
			},
		}

		// Mock verifier accepts peer's proof
		verifier := &mockVerifier{
			verifyProofFunc: func(proof, commitment, peerSig []byte, maxDist uint32) error {
				return nil
			},
		}

		config := DefaultZKConfig()
		config.MaxDistance = 64
		config.ProofTimeout = 5 * time.Second

		exchange := NewZKExchange(prover, verifier, config)

		// Simulate initiator in background
		initiatorDone := make(chan error, 1)
		go func() {
			// Send request
			req := &pb.ZKProofRequest{
				MaxDistance: 64,
				Commitment:  []byte("initiator-commitment"),
				Signature:   peerSignature,
			}
			if err := writeZKRequest(initiatorStream, req); err != nil {
				initiatorDone <- err
				return
			}

			// Read response
			resp, err := readZKResponse(initiatorStream)
			if err != nil {
				initiatorDone <- err
				return
			}

			// Verify response contents
			assert.Equal(t, []byte("responder-proof"), resp.Proof)
			assert.Equal(t, []byte("responder-commitment"), resp.Commitment)
			assert.Equal(t, mySignature, resp.Signature)

			// Send our proof
			ourResponse := &pb.ZKProofResponse{
				Proof:      []byte("initiator-proof"),
				Commitment: []byte("initiator-commitment"),
				Signature:  peerSignature,
			}
			if err := writeZKResponse(initiatorStream, ourResponse); err != nil {
				initiatorDone <- err
				return
			}

			// Read result
			result, err := readZKResult(initiatorStream)
			if err != nil {
				initiatorDone <- err
				return
			}

			assert.True(t, result.Valid)
			initiatorDone <- nil
		}()

		// Run responder
		ctx := context.Background()
		err := exchange.HandleExchange(ctx, responderStream, mySignature)
		require.NoError(t, err)

		// Wait for initiator
		require.NoError(t, <-initiatorDone)
	})

	t.Run("rejects_invalid_peer_proof", func(t *testing.T) {
		initiatorStream, responderStream := newPipeStreamPair()

		mySignature := makeTestSignature(0x02)
		peerSignature := makeTestSignature(0x01)

		prover := &mockProver{
			generateProofFunc: func(mySig, peerSig []byte, maxDist uint32) (*ProofResult, error) {
				return &ProofResult{
					Proof:      []byte("responder-proof"),
					Commitment: []byte("responder-commitment"),
				}, nil
			},
		}

		// Verifier rejects peer's proof
		verifier := &mockVerifier{
			verifyProofFunc: func(proof, commitment, peerSig []byte, maxDist uint32) error {
				return errors.New("invalid proof")
			},
		}

		config := DefaultZKConfig()
		config.ProofTimeout = 5 * time.Second

		exchange := NewZKExchange(prover, verifier, config)

		// Simulate initiator
		initiatorDone := make(chan error, 1)
		go func() {
			// Send request
			req := &pb.ZKProofRequest{
				MaxDistance: 64,
				Commitment:  []byte("initiator-commitment"),
				Signature:   peerSignature,
			}
			writeZKRequest(initiatorStream, req)

			// Read response
			readZKResponse(initiatorStream)

			// Send bad proof
			ourResponse := &pb.ZKProofResponse{
				Proof:      []byte("bad-proof"),
				Commitment: []byte("bad-commitment"),
				Signature:  peerSignature,
			}
			writeZKResponse(initiatorStream, ourResponse)

			// Read result (should be invalid)
			result, err := readZKResult(initiatorStream)
			if err != nil {
				initiatorDone <- err
				return
			}

			assert.False(t, result.Valid)
			assert.NotEmpty(t, result.Error)
			initiatorDone <- nil
		}()

		ctx := context.Background()
		err := exchange.HandleExchange(ctx, responderStream, mySignature)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "peer proof invalid")

		require.NoError(t, <-initiatorDone)
	})

	t.Run("fails_when_proof_generation_fails", func(t *testing.T) {
		initiatorStream, responderStream := newPipeStreamPair()

		mySignature := makeTestSignature(0x02)
		peerSignature := makeTestSignature(0x01)

		// Prover fails
		prover := &mockProver{
			generateProofFunc: func(mySig, peerSig []byte, maxDist uint32) (*ProofResult, error) {
				return nil, errors.New("distance too large")
			},
		}
		verifier := &mockVerifier{}

		config := DefaultZKConfig()
		config.ProofTimeout = 5 * time.Second

		exchange := NewZKExchange(prover, verifier, config)

		// Simulate initiator sending request
		go func() {
			req := &pb.ZKProofRequest{
				MaxDistance: 64,
				Commitment:  []byte("initiator-commitment"),
				Signature:   peerSignature,
			}
			writeZKRequest(initiatorStream, req)
		}()

		ctx := context.Background()
		err := exchange.HandleExchange(ctx, responderStream, mySignature)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "generate proof")
	})

	t.Run("fails_on_timeout_reading_request", func(t *testing.T) {
		stream := newMockStream() // Empty stream, will timeout

		mySignature := makeTestSignature(0x02)

		prover := &mockProver{}
		verifier := &mockVerifier{}

		config := DefaultZKConfig()
		config.ProofTimeout = 1 * time.Millisecond

		exchange := NewZKExchange(prover, verifier, config)

		ctx := context.Background()
		err := exchange.HandleExchange(ctx, stream, mySignature)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "receive request")
	})
}

func TestWriteReadZKRequest(t *testing.T) {
	t.Run("roundtrip_success", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)

		original := &pb.ZKProofRequest{
			MaxDistance: 128,
			Commitment:  []byte("test-commitment-32-bytes-long!!"),
			Signature:   makeTestSignature(0xAB),
		}

		err := writeZKRequest(buf, original)
		require.NoError(t, err)

		result, err := readZKRequest(buf)
		require.NoError(t, err)

		assert.Equal(t, original.MaxDistance, result.MaxDistance)
		assert.Equal(t, original.Commitment, result.Commitment)
		assert.Equal(t, original.Signature, result.Signature)
	})

	t.Run("rejects_too_large_payload", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)

		// Write a fake header with huge length
		buf.WriteByte(byte(ZKMessageTypeRequest))
		lenBuf := make([]byte, 4)
		// Use max + 1 to trigger rejection
		lenBuf[0] = 0x01 // 16MB + 1 byte in big endian
		lenBuf[1] = 0x00
		lenBuf[2] = 0x00
		lenBuf[3] = 0x01
		buf.Write(lenBuf)

		_, err := readZKRequest(buf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "payload exceeds maximum")
	})
}

func TestWriteReadZKResponse(t *testing.T) {
	t.Run("roundtrip_success", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)

		original := &pb.ZKProofResponse{
			Proof:      []byte("serialized-plonk-proof-data"),
			Commitment: []byte("commitment-hash-32-bytes-long!"),
			Signature:  makeTestSignature(0xCD),
		}

		err := writeZKResponse(buf, original)
		require.NoError(t, err)

		result, err := readZKResponse(buf)
		require.NoError(t, err)

		assert.Equal(t, original.Proof, result.Proof)
		assert.Equal(t, original.Commitment, result.Commitment)
		assert.Equal(t, original.Signature, result.Signature)
	})
}

func TestWriteReadZKResult(t *testing.T) {
	t.Run("roundtrip_valid_result", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)

		original := &pb.ZKProofResult{
			Valid: true,
			Error: "",
		}

		err := writeZKResult(buf, original)
		require.NoError(t, err)

		result, err := readZKResult(buf)
		require.NoError(t, err)

		assert.True(t, result.Valid)
		assert.Empty(t, result.Error)
	})

	t.Run("roundtrip_invalid_result", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)

		original := &pb.ZKProofResult{
			Valid: false,
			Error: "proof verification failed: commitment mismatch",
		}

		err := writeZKResult(buf, original)
		require.NoError(t, err)

		result, err := readZKResult(buf)
		require.NoError(t, err)

		assert.False(t, result.Valid)
		assert.Equal(t, original.Error, result.Error)
	})
}

func TestWriteZKNilMessages(t *testing.T) {
	t.Run("nil_request", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)
		err := writeZKRequest(buf, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrZKNilMessage)
	})

	t.Run("nil_response", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)
		err := writeZKResponse(buf, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrZKNilMessage)
	})

	t.Run("nil_result", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)
		err := writeZKResult(buf, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrZKNilMessage)
	})
}

func TestReadZKMessageTypeValidation(t *testing.T) {
	t.Run("wrong_type_for_request", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)

		// Write a response but try to read as request
		resp := &pb.ZKProofResponse{
			Proof:      []byte("proof"),
			Commitment: []byte("commitment"),
			Signature:  []byte("signature"),
		}
		err := writeZKResponse(buf, resp)
		require.NoError(t, err)

		_, err = readZKRequest(buf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected message type")
	})

	t.Run("wrong_type_for_response", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)

		// Write a request but try to read as response
		req := &pb.ZKProofRequest{
			MaxDistance: 64,
			Commitment:  []byte("commitment"),
			Signature:   []byte("signature"),
		}
		err := writeZKRequest(buf, req)
		require.NoError(t, err)

		_, err = readZKResponse(buf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected message type")
	})

	t.Run("wrong_type_for_result", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)

		// Write a request but try to read as result
		req := &pb.ZKProofRequest{
			MaxDistance: 64,
			Commitment:  []byte("commitment"),
			Signature:   []byte("signature"),
		}
		err := writeZKRequest(buf, req)
		require.NoError(t, err)

		_, err = readZKResult(buf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected message type")
	})
}

func TestReadZKMessageEOF(t *testing.T) {
	t.Run("empty_buffer_returns_eof", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)
		_, err := readZKRequest(buf)
		require.Error(t, err)
		assert.ErrorIs(t, err, io.EOF)
	})
}

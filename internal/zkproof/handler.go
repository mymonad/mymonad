// Package zkproof provides zero-knowledge proof exchange functionality.
//
// Handler provides the libp2p stream handler for ZK proof exchanges.
// It integrates with the ZK service to handle incoming proof exchange requests
// from peers, enabling privacy-preserving signature verification.
//
// # Usage
//
// The handler is registered with a libp2p host during agent initialization:
//
//	handler := zkproof.NewHandler(zkService, getLocalSignature)
//	handler.RegisterStreamHandler(host)
//
// # Thread Safety
//
// Handler is safe for concurrent use from multiple goroutines.
// Each stream handler invocation operates independently.
package zkproof

import (
	"context"
	"log/slog"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"

	"github.com/mymonad/mymonad/pkg/zkproof"
)

// proverAdapter wraps pkg/zkproof.Prover to implement ProverInterface.
// This allows the internal exchange protocol to work with the pkg prover.
type proverAdapter struct {
	prover *zkproof.Prover
}

func (p *proverAdapter) GenerateProof(mySignature, peerSignature []byte, maxDistance uint32) (*ProofResult, error) {
	result, err := p.prover.GenerateProof(mySignature, peerSignature, maxDistance)
	if err != nil {
		return nil, err
	}
	return &ProofResult{
		Proof:      result.Proof,
		Commitment: result.Commitment,
	}, nil
}

// verifierAdapter wraps pkg/zkproof.Verifier to implement VerifierInterface.
// This allows the internal exchange protocol to work with the pkg verifier.
type verifierAdapter struct {
	verifier *zkproof.Verifier
}

func (v *verifierAdapter) VerifyProof(proofBytes, proverCommitment, peerSignature []byte, maxDistance uint32) error {
	return v.verifier.VerifyProof(proofBytes, proverCommitment, peerSignature, maxDistance)
}

// Handler manages libp2p stream handling for ZK proof exchanges.
// It wraps the ZKService and provides stream handler registration.
type Handler struct {
	zkService         *ZKService
	getLocalSignature func() []byte
}

// NewHandler creates a new Handler with the given ZKService and signature callback.
//
// The zkService provides proof generation and verification capabilities.
// The getLocalSignature callback returns the local node's LSH signature,
// which is used during proof exchanges to prove proximity to peers.
//
// Either parameter may be nil, in which case the handler will be created
// but will not register any stream handlers (safe no-op).
func NewHandler(zkService *ZKService, getLocalSignature func() []byte) *Handler {
	return &Handler{
		zkService:         zkService,
		getLocalSignature: getLocalSignature,
	}
}

// RegisterStreamHandler registers the ZK proof exchange handler with the host.
//
// If the ZKService is nil or disabled, no handler is registered and the
// function returns immediately. This allows the handler to be safely called
// during initialization even when ZK proofs are not configured.
//
// The registered handler processes incoming ZK proof exchange requests using
// the HandleExchange method from ZKExchange. It:
//  1. Receives a proof request from the connecting peer
//  2. Generates a proof using the local signature
//  3. Exchanges proofs with the peer
//  4. Records success/failure metrics
//
// The host parameter must not be nil when the service is enabled.
func (h *Handler) RegisterStreamHandler(host host.Host) {
	// Early return if service is nil or disabled
	if h.zkService == nil || !h.zkService.IsEnabled() {
		return
	}

	host.SetStreamHandler(ZKProtocolID, func(stream network.Stream) {
		defer stream.Close()

		peerID := stream.Conn().RemotePeer()

		// Get our local signature for this exchange
		var mySignature []byte
		if h.getLocalSignature != nil {
			mySignature = h.getLocalSignature()
		}

		if mySignature == nil {
			slog.Warn("ZK exchange handler: no local signature available",
				"peer", peerID,
			)
			h.zkService.RecordProofFailed()
			return
		}

		// Create adapters for the pkg prover/verifier to implement internal interfaces
		proverAdapt := &proverAdapter{prover: h.zkService.GetProver()}
		verifierAdapt := &verifierAdapter{verifier: h.zkService.GetVerifier()}

		// Create a new exchange instance for this stream
		exchange := NewZKExchange(
			proverAdapt,
			verifierAdapt,
			h.zkService.GetConfig(),
		)

		// Handle the incoming exchange as the responder
		if err := exchange.HandleExchange(context.Background(), stream, mySignature); err != nil {
			slog.Warn("ZK exchange handler failed",
				"peer", peerID,
				"error", err,
			)
			h.zkService.RecordProofFailed()
			return
		}

		h.zkService.RecordProofVerified()
		slog.Info("ZK exchange handled successfully", "peer", peerID)
	})
}

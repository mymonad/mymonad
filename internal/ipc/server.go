package ipc

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	pb "github.com/mymonad/mymonad/api/proto"
	"google.golang.org/grpc"
)

// MonadProvider is the interface for accessing the Monad.
type MonadProvider interface {
	GetMonad() (data []byte, version int64, err error)
	GetStatus() (ready bool, docsIndexed int64, state string)
}

// Server is the IPC gRPC server.
type Server struct {
	pb.UnimplementedMonadStoreServer

	sockPath string
	provider MonadProvider
	grpc     *grpc.Server
	listener net.Listener
}

// NewServer creates a new IPC server.
func NewServer(sockPath string, provider MonadProvider) (*Server, error) {
	// Remove existing socket if present (ignore "not exist" errors)
	if err := os.Remove(sockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}

	s := &Server{
		sockPath: sockPath,
		provider: provider,
		grpc:     grpc.NewServer(),
		listener: listener,
	}

	pb.RegisterMonadStoreServer(s.grpc, s)

	return s, nil
}

// Start begins serving requests.
func (s *Server) Start() error {
	return s.grpc.Serve(s.listener)
}

// Stop gracefully stops the server and removes the socket file.
// Returns an error if the socket file could not be removed.
func (s *Server) Stop() error {
	s.grpc.GracefulStop()
	if err := os.Remove(s.sockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// GetMonad implements the gRPC method.
func (s *Server) GetMonad(ctx context.Context, req *pb.GetMonadRequest) (*pb.GetMonadResponse, error) {
	data, version, err := s.provider.GetMonad()
	if err != nil {
		return nil, err
	}

	return &pb.GetMonadResponse{
		EncryptedMonad: data,
		Version:        version,
		LastUpdated:    time.Now().Unix(),
	}, nil
}

// Status implements the gRPC method.
func (s *Server) Status(ctx context.Context, req *pb.StatusRequest) (*pb.StatusResponse, error) {
	ready, docs, state := s.provider.GetStatus()

	return &pb.StatusResponse{
		Ready:             ready,
		DocumentsIndexed:  docs,
		LastScanTimestamp: time.Now().Unix(),
		State:             state,
	}, nil
}

package ipc

import (
	"context"
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
	// Remove existing socket if present
	os.Remove(sockPath)

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

// Stop gracefully stops the server.
func (s *Server) Stop() {
	s.grpc.GracefulStop()
	os.Remove(s.sockPath)
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

package grpcserver

import (
	"errors"
	"net"
)

// GRPCServerer is the interface for the grpc server
type GRPCServerer interface {
	Serve(net.Listener) error
	Stop()
}

// GRPCServicer is the interface for the grpc service
type GRPCServicer interface {
	Serve() error
	Close() error
}

// GRPCService is the implementation of the grpc service
type GRPCService struct {
	grpcServer   GRPCServerer
	grpcListener net.Listener
}

var _ GRPCServicer = &GRPCService{}

// Serve starts the grpc server
func (grpcService *GRPCService) Serve() error {
	return grpcService.grpcServer.Serve(grpcService.grpcListener)
}

// Close closes the grpc server
func (grpcService *GRPCService) Close() error {
	if grpcService.grpcServer == nil || grpcService.grpcListener == nil {
		if grpcService.grpcListener != nil {
			return grpcService.grpcListener.Close()
		}
		return errors.New("GRPC server or listener is nil")
	}
	grpcService.grpcServer.Stop()
	return grpcService.grpcListener.Close()
}

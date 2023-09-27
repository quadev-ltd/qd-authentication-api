package grpc_server

import (
	"net"

	"google.golang.org/grpc"
)

type GRPCServicer interface {
	Serve() error
	Close() error
}

type GRPCService struct {
	grpcServer   *grpc.Server
	grpcListener net.Listener
}

func (grpcServerFactory *GRPCService) Serve() error {
	return grpcServerFactory.grpcServer.Serve(grpcServerFactory.grpcListener)
}

func (grpcServerFactory *GRPCService) Close() error {
	if grpcServerFactory.grpcServer != nil {
		grpcServerFactory.grpcServer.Stop()
	}
	if grpcServerFactory.grpcListener != nil {
		return grpcServerFactory.grpcListener.Close()
	}
	return nil
}

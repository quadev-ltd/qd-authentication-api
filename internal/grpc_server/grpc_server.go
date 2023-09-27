package grpc_server

import (
	"errors"
	"net"
)

type GRPCServerInterface interface {
	Serve(net.Listener) error
	Stop()
}

type GRPCServicer interface {
	Serve() error
	Close() error
}

type GRPCService struct {
	grpcServer   GRPCServerInterface
	grpcListener net.Listener
}

func (grpcService *GRPCService) Serve() error {
	return grpcService.grpcServer.Serve(grpcService.grpcListener)
}

func (grpcService *GRPCService) Close() error {
	if grpcService.grpcServer == nil || grpcService.grpcListener == nil {
		if grpcService.grpcListener != nil {
			return grpcService.grpcListener.Close()
		}
		return errors.New("GRPC server or listener is nil.")
	} else {
		grpcService.grpcServer.Stop()
		return grpcService.grpcListener.Close()
	}
}

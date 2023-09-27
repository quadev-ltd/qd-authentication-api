package grpc_server

import (
	"net"
	"qd_authentication_api/internal/service"
	"qd_authentication_api/pb/gen/go/pb_authentication"

	"google.golang.org/grpc"
)

type GRPCServiceFactoryer interface {
	Create(grpcServerAddress string, authenticationService service.AuthenticationServicer) (GRPCServicer, error)
}

type GRPCServerFactory struct{}

func (grpcServerFactory *GRPCServerFactory) Create(
	grpcServerAddress string,
	authenticationService service.AuthenticationServicer,
) (GRPCServicer, error) {
	// Create a gRPC server with a registered authentication service
	authenticationServiceGRPCServer := AuthenticationServiceServer{
		AuthenticationService: authenticationService,
	}
	grpcServer := grpc.NewServer()
	pb_authentication.RegisterAuthenticationServiceServer(grpcServer, authenticationServiceGRPCServer)
	// Create a listener for the gRPC server which eventually will start accepting connections when server is served
	grpcListener, err := net.Listen("tcp", grpcServerAddress) // Choose a port for gRPC
	if err != nil {
		return nil, err
	}
	return &GRPCService{
		grpcServer:   grpcServer,
		grpcListener: grpcListener,
	}, nil
}

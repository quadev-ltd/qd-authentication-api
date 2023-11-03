package grpcserver

import (
	"net"
	"qd_authentication_api/internal/service"
	"qd_authentication_api/pb/gen/go/pb_authentication"

	"google.golang.org/grpc"
)

// Factoryer is the interfact for creating a gRPC server
type Factoryer interface {
	Create(grpcServerAddress string, authenticationService service.AuthenticationServicer) (GRPCServicer, error)
}

// Factory is the implementation of the gRPC server factory
type Factory struct{}

var _ Factoryer = &Factory{}

// Create creates a gRPC server
func (grpcServerFactory *Factory) Create(
	grpcServerAddress string,
	authenticationService service.AuthenticationServicer,
) (GRPCServicer, error) {
	// Create a gRPC server with a registered authentication service
	authenticationServiceGRPCServer := AuthenticationServiceServer{
		AuthenticationService: authenticationService,
	}
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(loggerInterceptor),
	)
	pb_authentication.RegisterAuthenticationServiceServer(grpcServer, authenticationServiceGRPCServer)
	// Create a listener for the gRPC server which eventually will start accepting connections when server is served
	grpcListener, err := net.Listen("tcp", grpcServerAddress)
	if err != nil {
		return nil, err
	}
	return &GRPCService{
		grpcServer:   grpcServer,
		grpcListener: grpcListener,
	}, nil
}

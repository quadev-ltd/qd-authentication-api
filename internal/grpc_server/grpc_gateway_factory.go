package grpc_server

import (
	"context"
	"qd_authentication_api/pb/gen/go/pb_authentication"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
)

type GRPCGatewayFactoryer interface {
	Create() (GRPCGatewayServicer, error)
}

type GRPCGatewayFactory struct{}

func (grpcGatewayFactory *GRPCGatewayFactory) Create(
	grpcServerAddress string,
	gatewayServerAddress string,
) (GRPCGatewayServicer, error) {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	mux := runtime.NewServeMux()
	// TODO deprecated
	opts := []grpc.DialOption{grpc.WithInsecure()}
	err := pb_authentication.RegisterAuthenticationServiceHandlerFromEndpoint(ctx, mux, grpcServerAddress, opts)
	if err != nil {
		cancel()
		return nil, err
	}
	return &GRPCGatewayService{
		gatewayServerAddress: gatewayServerAddress,
		mux:                  mux,
		cancel:               cancel,
	}, nil
}

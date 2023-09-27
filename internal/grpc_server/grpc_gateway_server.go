package grpc_server

import (
	"context"
	"errors"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

type GRPCGatewayServicer interface {
	Serve() error
	Close() error
}

type GRPCGatewayService struct {
	gatewayServerAddress string
	mux                  *runtime.ServeMux
	cancel               context.CancelFunc
}

func (grpcGatewayService *GRPCGatewayService) Serve() error {
	return http.ListenAndServe(grpcGatewayService.gatewayServerAddress, grpcGatewayService.mux)
}

func (grpcGatewayService *GRPCGatewayService) Close() error {
	if grpcGatewayService.cancel == nil {
		return errors.New("Function cancel is nil.")
	}
	grpcGatewayService.cancel()
	return nil
}

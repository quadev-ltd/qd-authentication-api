package grpc_server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

type GRPCGatewayServicer interface {
	Serve() error
	Close()
}

type GRPCGatewayService struct {
	gatewayServerAddress string
	mux                  *runtime.ServeMux
	cancel               context.CancelFunc
}

func (grpcGatewayService *GRPCGatewayService) Serve() error {
	return http.ListenAndServe(fmt.Sprintf(grpcGatewayService.gatewayServerAddress), grpcGatewayService.mux)
}

func (grpcGatewayService *GRPCGatewayService) Close() {
	grpcGatewayService.cancel()
}

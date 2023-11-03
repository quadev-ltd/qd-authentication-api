package application

import (
	"fmt"
	"qd_authentication_api/internal/config"
	grpcServerService "qd_authentication_api/internal/grpc_server"
	"qd_authentication_api/internal/service"

	"github.com/rs/zerolog/log"
)

type Applicationer interface {
	StartServers()
	Close()
	GetGRPCServerAddress() string
	GetGRPCGatewayAddress() string
}

type Application struct {
	grpcServiceServer  grpcServerService.GRPCServicer
	grpcServerAddress  string
	grpcGatewayServer  grpcServerService.GRPCServicer
	grpcGatewayAddress string
	service            service.Servicer
}

func NewApplication(config *config.Config) Applicationer {
	grpcServerAddress := fmt.Sprintf("%s:%s", config.GRPC.Host, config.GRPC.Port)
	grpcGatewayAddress := fmt.Sprintf("%s:%s", config.REST.Host, config.REST.Port)

	service, err := (&service.ServiceFactory{}).CreateService(config)
	if err != nil {
		log.Err(fmt.Errorf("Failed to create authentication service: %v", err))
	}
	grpcServiceServer, err := (&grpcServerService.GRPCServerFactory{}).Create(
		grpcServerAddress,
		service.GetAuthenticationService(),
	)
	if err != nil {
		log.Err(fmt.Errorf("Failed to create grpc server: %v", err))
	}
	grpcGatewayServer, err := (&grpcServerService.GRPCGatewayFactory{}).Create(grpcServerAddress, grpcGatewayAddress)
	if err != nil {
		log.Err(fmt.Errorf("Failed to create grpc gateway server: %v", err))
	}

	return &Application{
		grpcServiceServer:  grpcServiceServer,
		grpcServerAddress:  grpcServerAddress,
		grpcGatewayServer:  grpcGatewayServer,
		grpcGatewayAddress: grpcGatewayAddress,
		service:            service,
	}
}

func (aplication *Application) StartServers() {
	if (aplication.grpcServiceServer == nil) || (aplication.grpcGatewayServer == nil) {
		log.Error().Msg("Servers are not created")
	}
	go func() {
		log.Printf("Starting gRPC server on %s:...", aplication.grpcServerAddress)
		err := aplication.grpcServiceServer.Serve()
		if err != nil {
			log.Err(fmt.Errorf("Failed to serve grpc server: %v", err))
		}
	}()

	log.Printf("Starting gRPC-gateway server on %s:...", aplication.grpcGatewayAddress)
	err := aplication.grpcGatewayServer.Serve()
	if err != nil {
		log.Err(fmt.Errorf("Failed to serve grpc gateway server: %v", err))
	}
}

func (aplication *Application) Close() {
	switch {
	case aplication.service == nil:
		log.Err(fmt.Errorf("Service is not created"))
	case aplication.grpcServiceServer == nil:
		log.Err(fmt.Errorf("gRPC server is not created"))
	case aplication.grpcGatewayServer == nil:
		log.Err(fmt.Errorf("gRPC gateway server is not created"))
	}
	aplication.service.Close()
	aplication.grpcServiceServer.Close()
	aplication.grpcGatewayServer.Close()
}

func (aplication *Application) GetGRPCServerAddress() string {
	return aplication.grpcServerAddress
}

func (aplication *Application) GetGRPCGatewayAddress() string {
	return aplication.grpcGatewayAddress
}

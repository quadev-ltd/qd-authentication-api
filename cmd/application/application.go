package application

import (
	"fmt"
	"qd_authentication_api/internal/config"
	grpcServerService "qd_authentication_api/internal/grpcserver"
	"qd_authentication_api/internal/service"

	"github.com/rs/zerolog/log"
)

// Applicationer provides the main functions to start the application
type Applicationer interface {
	StartServer()
	Close()
	GetGRPCServerAddress() string
}

// Application is the main application
type Application struct {
	grpcServiceServer grpcServerService.GRPCServicer
	grpcServerAddress string
	service           service.Servicer
}

// NewApplication creates a new application
func NewApplication(config *config.Config) Applicationer {
	grpcServerAddress := fmt.Sprintf("%s:%s", config.GRPC.Host, config.GRPC.Port)

	service, err := (&service.Factory{}).CreateService(config)
	if err != nil {
		log.Err(fmt.Errorf("Failed to create authentication service: %v", err))
	}
	grpcServiceServer, err := (&grpcServerService.Factory{}).Create(
		grpcServerAddress,
		service.GetAuthenticationService(),
	)
	if err != nil {
		log.Err(fmt.Errorf("Failed to create grpc server: %v", err))
	}

	return &Application{
		grpcServiceServer: grpcServiceServer,
		grpcServerAddress: grpcServerAddress,
		service:           service,
	}
}

// StartServer starts the gRPC server
func (aplication *Application) StartServer() {
	go func() {
		log.Printf("Starting gRPC server on %s:...", aplication.grpcServerAddress)
		err := aplication.grpcServiceServer.Serve()
		if err != nil {
			log.Err(fmt.Errorf("Failed to serve grpc server: %v", err))
		}
	}()
}

// Close closes the gRPC server and services used by the application
func (aplication *Application) Close() {
	switch {
	case aplication.service == nil:
		log.Err(fmt.Errorf("Service is not created"))
	case aplication.grpcServiceServer == nil:
		log.Err(fmt.Errorf("gRPC server is not created"))
	}
	aplication.service.Close()
	aplication.grpcServiceServer.Close()
}

// GetGRPCServerAddress returns the gRPC server address
func (aplication *Application) GetGRPCServerAddress() string {
	return aplication.grpcServerAddress
}

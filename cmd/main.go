package main

import (
	"fmt"
	"log"

	"qd_authentication_api/internal/config"
	grpcServerService "qd_authentication_api/internal/grpc_server"
	"qd_authentication_api/internal/service"
)

func main() {
	// grpclog.SetLogger(log.New(os.Stdout, "grpc: ", log.LstdFlags))

	var config config.Config
	config.Load()

	grpcServerAddress := fmt.Sprintf("%s:%s", config.GRPC.Host, config.GRPC.Port)
	grpcGatewayAddress := fmt.Sprintf("%s:%s", config.REST.Host, config.REST.Port)

	service, err := (&service.ServiceFactory{}).CreateService(&config)
	if err != nil {
		log.Fatalf("Failed to create authentication service: %v", err)
	}
	defer service.Close()

	grpcServiceServer, err := (&grpcServerService.GRPCServerFactory{}).Create(
		grpcServerAddress,
		service.GetAuthenticationService(),
	)
	if err != nil {
		log.Fatalf("Failed to create grpc server: %v", err)
	}
	defer grpcServiceServer.Close()
	go func() {
		log.Printf("Starting gRPC server on port %s:...", config.GRPC.Port)
		err := grpcServiceServer.Serve()
		if err != nil {
			log.Fatalf("Failed to serve grpc server: %v", err)
		}
	}()

	grpcGatewayServer, err := (&grpcServerService.GRPCGatewayFactory{}).Create(grpcServerAddress, grpcGatewayAddress)
	if err != nil {
		log.Fatalf("Failed to create grpc gateway server: %v", err)
	}
	defer grpcGatewayServer.Close()
	log.Printf("Starting gRPC-gateway server on port %s:...", config.REST.Port)
	err = grpcGatewayServer.Serve()
	if err != nil {
		log.Fatalf("Failed to serve grpc gateway server: %v", err)
	}
}

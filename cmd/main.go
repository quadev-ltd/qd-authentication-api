package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"

	"qd_authentication_api/internal/config"
	grpcServerService "qd_authentication_api/internal/grpc_server"
	mongoRepository "qd_authentication_api/internal/repository/mongo"
	"qd_authentication_api/internal/service"
	"qd_authentication_api/pb/gen/go/pb_authentication"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/grpc"
)

func main() {
	var config config.Config
	config.Load()

	client, error := mongo.Connect(context.Background(), options.Client().ApplyURI(config.MongoURI))
	if error != nil {
		log.Fatal(error)
	}
	defer client.Disconnect(context.Background())

	userRepo := mongoRepository.NewMongoUserRepository(client)
	baseUrl := fmt.Sprintf("%s://%s:%s", config.App.Protocol, config.REST.Host, config.REST.Port)
	emailServiceConfig := service.EmailServiceConfig{
		AppName:  config.App.Name,
		BaseUrl:  baseUrl,
		From:     config.SMTP.Username,
		Password: config.SMTP.Password,
		Host:     config.SMTP.Host,
		Port:     config.SMTP.Port,
	}
	emailService := service.NewEmailService(emailServiceConfig, &service.SmtpService{})
	authenticationService := service.NewAuthenticationService(emailService, userRepo, config.Authentication.Key)

	// TODO deprecated
	// grpclog.SetLogger(log.New(os.Stdout, "grpc: ", log.LstdFlags))

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux := runtime.NewServeMux()
	// TODO deprecated
	opts := []grpc.DialOption{grpc.WithInsecure()}
	grpcServerAddress := fmt.Sprintf("%s:%s", config.GRPC.Host, config.GRPC.Port)
	err := pb_authentication.RegisterAuthenticationServiceHandlerFromEndpoint(ctx, mux, grpcServerAddress, opts)
	if err != nil {
		log.Fatalf("Failed to register gRPC-gateway handler: %v", err)
	}

	// Create a gRPC server
	authenticationServiceGRPCServer := grpcServerService.AuthenticationServiceServer{
		AuthenticationService: authenticationService,
	}
	grpcServer := grpc.NewServer()
	pb_authentication.RegisterAuthenticationServiceServer(grpcServer, authenticationServiceGRPCServer)

	// Start the gRPC server
	grpcListener, err := net.Listen("tcp", grpcServerAddress) // Choose a port for gRPC
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer grpcListener.Close()

	go func() {
		log.Printf("Starting the GRPC server on %s:...", config.GRPC.Port)
		if err := grpcServer.Serve(grpcListener); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	// Start the gRPC-gateway server
	log.Printf("Starting gRPC-gateway server on %s:...", config.REST.Port)
	if err := http.ListenAndServe(fmt.Sprintf("%s:%s", config.REST.Host, config.REST.Port), mux); err != nil {
		log.Fatalf("gRPC-gateway server failed: %v", err)
	}
}

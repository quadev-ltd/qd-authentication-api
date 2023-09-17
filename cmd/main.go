package main

import (
	"context"
	"log"
	"net"

	"qd_authentication_api/internal/config"
	"qd_authentication_api/internal/pb"
	mongoRepository "qd_authentication_api/internal/repository/mongo"
	server_grpc "qd_authentication_api/internal/server_grpc"
	"qd_authentication_api/internal/service"

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
	emailServiceConfig := service.EmailServiceConfig{
		AppName:  config.App.Name,
		BaseUrl:  config.App.BaseUrl,
		From:     config.SMTP.Username,
		Password: config.SMTP.Password,
		Host:     config.SMTP.Host,
		Port:     config.SMTP.Port,
	}
	emailService := service.NewEmailService(emailServiceConfig, &service.SmtpService{})
	authenticationService := service.NewAuthenticationService(emailService, userRepo)

	// Create a gRPC server
	authenticationServiceGRPCServer := server_grpc.AuthenticationServiceServer{
		AuthenticationService: authenticationService,
	}
	grpcServer := grpc.NewServer()
	pb.RegisterAuthenticationServiceServer(grpcServer, authenticationServiceGRPCServer)

	// Start the gRPC server
	grpcListener, err := net.Listen("tcp", "127.0.0.1:8080") // Choose a port for gRPC
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer grpcListener.Close()
	log.Println("Starting the server on :8080...")
	if err := grpcServer.Serve(grpcListener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

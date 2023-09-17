package main

import (
	"context"
	"log"
	"qd_authentication_api/internal/pb"

	"google.golang.org/grpc"
)

func main() {
	conn, err := grpc.Dial("localhost:8080", grpc.WithInsecure()) // Connect to your gRPC server
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewAuthenticationServiceClient(conn)

	// You can now use the client to call your gRPC methods
	ctx := context.Background()
	// registerResponse, err := client.Register(ctx, &pb.RegisterRequest{
	// 	Email:     "gusfran17@hotmail.com",
	// 	Password:  "password123",
	// 	FirstName: "John",
	// 	LastName:  "Doe",
	// 	// Populate other fields as needed
	// })
	authenticateResponse, err := client.Authenticate(ctx, &pb.AuthenticateRequest{
		Email:    "gusfran17@gmail.com",
		Password: "password",
	})

	if err != nil {
		log.Fatalf("Register failed: %v", err)
	}

	// Handle the response
	log.Printf("Register response: %v", authenticateResponse)
}

package main

import (
	"context"
	"log"
	"qd_authentication_api/pb/gen/go/pb_authentication"

	"google.golang.org/grpc"
)

func main() {
	conn, err := grpc.Dial("localhost:8081", grpc.WithInsecure()) // Connect to your gRPC server
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	client := pb_authentication.NewAuthenticationServiceClient(conn)

	// You can now use the client to call your gRPC methods
	ctx := context.Background()
	// registerResponse, err := client.Register(ctx, &pb_authentication.RegisterRequest{
	// 	Email:     "gusfran17@gmail.com",
	// 	Password:  "password123",
	// 	FirstName: "John",
	// 	LastName:  "Doe",
	// 	// Populate other fields as needed
	// })
	authenticateResponse, err := client.Authenticate(ctx, &pb_authentication.AuthenticateRequest{
		Email:    "gusfran17@gmail.com",
		Password: "password123",
	})

	if err != nil {
		log.Fatalf("Register failed: %v", err)
	}

	// Handle the response
	log.Printf("Authentication response:\n\n\n\n%v", authenticateResponse)
	// log.Printf("Register response:\n\n\n\n%v", registerResponse)
}

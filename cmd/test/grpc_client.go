package main

import (
	"context"
	"log"

	pkgLogger "github.com/gustavo-m-franco/qd-common/pkg/log"
	"google.golang.org/grpc"

	"qd-authentication-api/pb/gen/go/pb_authentication"
)

func main() {
	conn, err := grpc.Dial("localhost:9090", grpc.WithInsecure()) // Connect to your gRPC server
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	client := pb_authentication.NewAuthenticationServiceClient(conn)

	// You can now use the client to call your gRPC methods
	ctx := pkgLogger.AddCorrelationIDToContext(context.Background(), "1234567890")

	// Registration

	registerResponse, err := client.Register(ctx, &pb_authentication.RegisterRequest{
		Email:     "gusfran17@gmail.com",
		Password:  "Password123!",
		FirstName: "John",
		LastName:  "Doe",
		// Populate other fields as needed
	})

	if err != nil {
		log.Fatalf("Register failed: %v", err)
	}

	// Handle the response
	log.Printf("Register response:\n\n\n\n%v", registerResponse)

	// // Authentication

	// authenticateResponse, err := client.Authenticate(ctx, &pb_authentication.AuthenticateRequest{
	// 	Email:    "gusfran17@gmail.com",
	// 	Password: "password123",
	// })
	// if err != nil {
	// 	log.Fatalf("Register failed: %v", err)
	// }
	// // Handle the response
	// log.Printf("Authentication response:\n\n\n\n%v", authenticateResponse)
}

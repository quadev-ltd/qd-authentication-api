package main

import (
	"context"
	"fmt"
	"log"
	"os"

	pkgLogger "github.com/quadev-ltd/qd-common/pkg/log"
	commonTLS "github.com/quadev-ltd/qd-common/pkg/tls"

	"qd-authentication-api/pb/gen/go/pb_authentication"
)

func main() {
	// get env variables
	tlsEnabled := os.Getenv("TLS_ENABLED")
	conn, err := commonTLS.CreateGRPCConnection("qd.authentication.api:9090", tlsEnabled == "true")
	if err != nil {
		log.Fatal(fmt.Errorf("Could not connect to email service: %v", err))
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

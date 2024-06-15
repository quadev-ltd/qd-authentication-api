package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/quadev-ltd/qd-common/pb/gen/go/pb_authentication"
	commonLogger "github.com/quadev-ltd/qd-common/pkg/log"
	commonTLS "github.com/quadev-ltd/qd-common/pkg/tls"
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
	ctx := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), "1234567890")

	// // // Registration

	// registerResponse, err := client.Register(ctx, &pb_authentication.RegisterRequest{
	// 	Email:       "gusfran17@gmail.com",
	// 	Password:    "Password123!",
	// 	FirstName:   "John",
	// 	LastName:    "Doe",
	// 	DateOfBirth: timestamppb.New(time.Now().AddDate(-20, 0, 0)),
	// 	// Populate other fields as needed
	// })

	// if err != nil {
	// 	log.Fatalf("Register failed: %v", err)
	// }

	// // Handle the response
	// log.Printf("Register response:\n\n\n\n%v", registerResponse)

	// // Authentication

	// refreshTokenResponse, err := client.RefreshToken(ctx, &pb_authentication.RefreshTokenRequest{
	// 	// Token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6Imd1c2ZyYW4xN0BnbWFpbC5jb20iLCJleHBpcnkiOjE3MTAwODE1MjUsImlhdCI6MTcwOTQ3NjcyNSwibm9uY2UiOiI0YWJiMGNlMy01ODY5LTQ5MTMtYWM5Yi00ZjQwMzg0MmEzN2MifQ.vZx7SdPNBzL64DwmwwOdwagbYuwKqYZD0yD5kibf2OLaMVKZuL_D-qYWyp-7MoJSzwjG3s_RhCAeRFYBQYEQwFKDVAt_NogLuwuPO-xlCaegsCMETq_v1t0uEOnsFgVnK21w0zq8yCXpT8jsi7MSTwPXOBh7TCR_ICsu-ED86coL47-gTdzgir711_JEqq7IdC_B5mpbAe5bTSsB0wArIpseRUunDM41gd6W8F5hdPNrviDgmUsOYm3PrG4SuPYmRlk3rrqSh1-xmhGmfe4J2BjqNvgleIrET7n7CP0eChn75t4_gSoWMitDlfE_KBKsX-f6YZWKDfkWrwd0Vvnf9g",
	// })
	// if err != nil {
	// 	log.Fatalf("Refresh token failed: %v", err)
	// }
	// // Handle the response
	// log.Printf("Refresh token response:\n\n\n\n%v", refreshTokenResponse)

	// // AuthenticateWithFirebase
	authenticateWithFirebaseResponse, err := client.AuthenticateWithFirebase(ctx, &pb_authentication.AuthenticateWithFirebaseRequest{
		Email:     "gusfran17@gmail.com",
		FirstName: "Gustavo",
		LastName:  "Franco",
		IdToken:   "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMzMDUxMThiZTBmNTZkYzA4NGE0NmExN2RiNzU1NjVkNzY4YmE2ZmUiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoiR3VzdGF2byBGcmFuY28iLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUNnOG9jSzFBamNpeEVTRXBnM1ItT2tyMGZpSDl3cHRBVDB3WW1FZV9RSVkxSF9nRE1SN3FfcTV4dz1zOTYtYyIsImlzcyI6Imh0dHBzOi8vc2VjdXJldG9rZW4uZ29vZ2xlLmNvbS9xdWFkZXZhcHAtZGV2IiwiYXVkIjoicXVhZGV2YXBwLWRldiIsImF1dGhfdGltZSI6MTcxNzUwODAwMCwidXNlcl9pZCI6ImtvRkZ2ZEZqUjJNblJYcmNoeE11RjZkbHVNYTIiLCJzdWIiOiJrb0ZGdmRGalIyTW5SWHJjaHhNdUY2ZGx1TWEyIiwiaWF0IjoxNzE3NTA4MDAwLCJleHAiOjE3MTc1MTE2MDAsImVtYWlsIjoiZ3VzZnJhbjE3QGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJmaXJlYmFzZSI6eyJpZGVudGl0aWVzIjp7Imdvb2dsZS5jb20iOlsiMTA5OTA3NjA1MTYwNTY1NzkxMDc0Il0sImVtYWlsIjpbImd1c2ZyYW4xN0BnbWFpbC5jb20iXX0sInNpZ25faW5fcHJvdmlkZXIiOiJnb29nbGUuY29tIn19.QmVQpsy3Gm-0oj_DZgdRiF0HB9D2FbDhn6G2M8UagP8uFQEdqDF2k0aGMA1zVnv27XDJfFqAuF4LqXcIBFoDJ4D7qyMUlacRfe27IHVu3wTXagMhibtK060m7eUjIWBHH3NMieUiPdklTlKbN-ZJ01S1My-NbtUCfLLrVXPbl9h1B5i_JRe56r1zVeOoBSlOb0XyZJaPc5fzI7RUYpbQgj7DzD39QBhGb_nZyPjulF87jGBM4hKf64cT0p9t88A7lYuj-uGVVOpCzgmtVaXxgg0T47DVrWJyMURx8xWBFJ_MVZg8ivt7G45aRDFCUk48sXZmTagzvXV4ypIjE3MncQ",
	})
	if err != nil {
		log.Fatalf("Authenticate with firebase failed: %v", err)
	}
	// Handle the response
	log.Printf("Authenticate with firebase response:\n\n\n\n%v", authenticateWithFirebaseResponse)
}

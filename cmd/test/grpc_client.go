package main

import (
	"context"
	"fmt"
	"log"
	"os"

	commonLogger "github.com/quadev-ltd/qd-common/pkg/log"
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

	refreshTokenResponse, err := client.RefreshToken(ctx, &pb_authentication.RefreshTokenRequest{
		// Token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6Imd1c2ZyYW4xN0BnbWFpbC5jb20iLCJleHBpcnkiOjE3MTAwODE1MjUsImlhdCI6MTcwOTQ3NjcyNSwibm9uY2UiOiI0YWJiMGNlMy01ODY5LTQ5MTMtYWM5Yi00ZjQwMzg0MmEzN2MifQ.vZx7SdPNBzL64DwmwwOdwagbYuwKqYZD0yD5kibf2OLaMVKZuL_D-qYWyp-7MoJSzwjG3s_RhCAeRFYBQYEQwFKDVAt_NogLuwuPO-xlCaegsCMETq_v1t0uEOnsFgVnK21w0zq8yCXpT8jsi7MSTwPXOBh7TCR_ICsu-ED86coL47-gTdzgir711_JEqq7IdC_B5mpbAe5bTSsB0wArIpseRUunDM41gd6W8F5hdPNrviDgmUsOYm3PrG4SuPYmRlk3rrqSh1-xmhGmfe4J2BjqNvgleIrET7n7CP0eChn75t4_gSoWMitDlfE_KBKsX-f6YZWKDfkWrwd0Vvnf9g",
	})
	if err != nil {
		log.Fatalf("Refresh token failed: %v", err)
	}
	// Handle the response
	log.Printf("Refresh token response:\n\n\n\n%v", refreshTokenResponse)

	// //
}

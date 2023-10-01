package application

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"qd_authentication_api/internal/config"
	"qd_authentication_api/internal/model"
	"qd_authentication_api/pb/gen/go/pb_authentication"
	"testing"
	"time"

	"github.com/benweissmann/memongo"
	"github.com/mhale/smtpd"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/grpc"
)

func isServerUp(addr string) bool {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func waitForServerUp(application Applicationer) {
	maxWaitTime := 10 * time.Second
	startTime := time.Now()

	for {
		if time.Since(startTime) > maxWaitTime {
			log.Fatal("Server didn't start within the specified time.")
		}

		if isServerUp(application.GetGRPCServerAddress()) {
			log.Println("Server is up.")
			break
		}

		time.Sleep(1 * time.Second)
	}
}

func startMockMongoServer() (*memongo.Server, error) {
	mongoServer, err := memongo.StartWithOptions(
		&memongo.Options{
			LogLevel:     10,
			MongoVersion: "4.0.5",
		},
	)
	if err != nil {
		return nil, err
	}
	return mongoServer, nil
}

func startMockSMTPServer(mockSMTPServerHost string, mockSMTPServerPort string) *smtpd.Server {
	authMechanisms := map[string]bool{
		"PLAIN": true,
		"LOGIN": true,
	}
	smtpServer := smtpd.Server{
		Addr:     fmt.Sprintf("%s:%s", mockSMTPServerHost, mockSMTPServerPort),
		Appname:  "Mock SMTP Server",
		Hostname: mockSMTPServerPort,
		Handler: func(remoteAddress net.Addr, from string, to []string, data []byte) error {
			return nil
		},
		AuthHandler: func(remoteAddress net.Addr, mechanism string, username []byte, password []byte, shared []byte) (bool, error) {
			return true, nil
		},
		AuthRequired: true,
		AuthMechs:    authMechanisms,
	}

	go func() {
		log.Printf("Starting mock SMTP server %s... ", fmt.Sprintf("%s:%s", mockSMTPServerHost, mockSMTPServerPort))
		err := smtpServer.ListenAndServe()
		if err != nil {
			log.Fatal(err)
		}
	}()
	return &smtpServer
}

func TestRegister(t *testing.T) {
	os.Setenv("APP_ENV", "test")

	mongoServer, err := startMockMongoServer()
	assert.NoError(t, err)
	assert.NotNil(t, mongoServer)
	defer mongoServer.Stop()

	var config config.Config
	config.Load("../../internal/config")
	config.DB.URI = mongoServer.URI()

	smtpServer := startMockSMTPServer(config.SMTP.Host, config.SMTP.Port)
	defer smtpServer.Close()

	application := NewApplication(&config)
	go func() {
		application.StartServers()
	}()
	defer application.Close()

	waitForServerUp(application)

	email := "test@test.com"
	password := "test123"

	t.Run("Register_Success", func(t *testing.T) {
		connection, err := grpc.Dial(application.GetGRPCServerAddress(), grpc.WithInsecure())
		assert.NoError(t, err)

		client := pb_authentication.NewAuthenticationServiceClient(connection)
		ctx := context.Background()

		registerResponse, err := client.Register(ctx, &pb_authentication.RegisterRequest{
			Email:     email,
			Password:  password,
			FirstName: "John",
			LastName:  "Doe",
			// Populate other fields as needed
		})

		assert.NoError(t, err)
		assert.Equal(t, registerResponse.Success, true)
		assert.Equal(t, registerResponse.Message, "Registration successful")
	})

	t.Run("Register_Failure_Already_Existing_User", func(t *testing.T) {
		connection, err := grpc.Dial(application.GetGRPCServerAddress(), grpc.WithInsecure())
		assert.NoError(t, err)

		client := pb_authentication.NewAuthenticationServiceClient(connection)
		ctx := context.Background()

		registerResponse, err := client.Register(ctx, &pb_authentication.RegisterRequest{
			Email:     email,
			Password:  password,
			FirstName: "John",
			LastName:  "Doe",
			// Populate other fields as needed
		})

		assert.Error(t, err)
		assert.Nil(t, registerResponse)
		assert.Equal(t, err.Error(), "rpc error: code = InvalidArgument desc = Registration failed: email already in use")
	})

	t.Run("Verify_Email_Error_Wrong_Token", func(t *testing.T) {
		connection, err := grpc.Dial(application.GetGRPCServerAddress(), grpc.WithInsecure())
		assert.NoError(t, err)

		client := pb_authentication.NewAuthenticationServiceClient(connection)
		ctx := context.Background()

		registerResponse, err := client.VerifyEmail(ctx, &pb_authentication.VerifyEmailRequest{
			VerificationToken: "1234567890",
		})

		assert.Error(t, err)
		assert.Nil(t, registerResponse)
		assert.Equal(t, err.Error(), "rpc error: code = InvalidArgument desc = Invalid verification token")
	})

	t.Run("Verify_Email_Success", func(t *testing.T) {
		client, err := mongo.NewClient(options.Client().ApplyURI(mongoServer.URI()))
		if err != nil {
			log.Fatal(err)
		}

		err = client.Connect(context.Background())
		if err != nil {
			log.Fatal(err)
		}
		defer client.Disconnect(context.Background())

		collection := client.Database("qd_authentication").Collection("user")
		var foundUser model.User
		err = collection.FindOne(context.Background(), bson.M{"email": email}).Decode(&foundUser)
		if err != nil {
			log.Fatal(err)
		}

		connection, err := grpc.Dial(application.GetGRPCServerAddress(), grpc.WithInsecure())
		assert.NoError(t, err)

		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)

		registerResponse, err := grpcClient.VerifyEmail(context.Background(), &pb_authentication.VerifyEmailRequest{
			VerificationToken: foundUser.VerificationToken,
		})

		assert.NoError(t, err)
		assert.NotNil(t, registerResponse)
		assert.Equal(t, registerResponse.Message, "Email verified successfully")
		assert.Equal(t, registerResponse.Success, true)
	})

	t.Run("Authenticate_Success", func(t *testing.T) {
		client, err := mongo.NewClient(options.Client().ApplyURI(mongoServer.URI()))
		if err != nil {
			log.Fatal(err)
		}

		err = client.Connect(context.Background())
		if err != nil {
			log.Fatal(err)
		}
		defer client.Disconnect(context.Background())

		collection := client.Database("qd_authentication").Collection("user")
		var foundUser model.User
		err = collection.FindOne(context.Background(), bson.M{"email": email}).Decode(&foundUser)
		if err != nil {
			log.Fatal(err)
		}

		connection, err := grpc.Dial(application.GetGRPCServerAddress(), grpc.WithInsecure())
		assert.NoError(t, err)

		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)

		registerResponse, err := grpcClient.Authenticate(context.Background(), &pb_authentication.AuthenticateRequest{
			Email:    foundUser.Email,
			Password: password,
		})

		assert.NoError(t, err)
		assert.NotNil(t, registerResponse)
		assert.NotNil(t, registerResponse.AuthToken)
		assert.NotNil(t, registerResponse.RefreshToken)
		assert.Equal(t, foundUser.Email, registerResponse.UserEmail)
	})

	t.Run("Authenticate_Error", func(t *testing.T) {
		client, err := mongo.NewClient(options.Client().ApplyURI(mongoServer.URI()))
		if err != nil {
			log.Fatal(err)
		}

		err = client.Connect(context.Background())
		if err != nil {
			log.Fatal(err)
		}
		defer client.Disconnect(context.Background())

		collection := client.Database("qd_authentication").Collection("user")
		var foundUser model.User
		err = collection.FindOne(context.Background(), bson.M{"email": email}).Decode(&foundUser)
		if err != nil {
			log.Fatal(err)
		}

		connection, err := grpc.Dial(application.GetGRPCServerAddress(), grpc.WithInsecure())
		assert.NoError(t, err)

		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)

		registerResponse, err := grpcClient.Authenticate(context.Background(), &pb_authentication.AuthenticateRequest{
			Email:    foundUser.Email,
			Password: "password",
		})

		assert.Error(t, err)
		assert.Nil(t, registerResponse)
		assert.Equal(t, "rpc error: code = Unauthenticated desc = Invalid email or password", err.Error())
	})

}

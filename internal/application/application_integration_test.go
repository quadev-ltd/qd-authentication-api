package application

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	commonConfig "github.com/quadev-ltd/qd-common/pkg/config"
	commonLogger "github.com/quadev-ltd/qd-common/pkg/log"
	commonTLS "github.com/quadev-ltd/qd-common/pkg/tls"
	commonUtil "github.com/quadev-ltd/qd-common/pkg/util"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/tryvium-travels/memongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"qd-authentication-api/internal/config"
	"qd-authentication-api/internal/model"
	"qd-authentication-api/pb/gen/go/pb_authentication"
	"qd-authentication-api/pb/gen/go/pb_email"
)

const wrongEmail = "wrong@email.com"

var jwtToken string

func isServerUp(test *testing.T, addr string, tlsEnabled bool) bool {
	if tlsEnabled {
		tlsConfig, err := commonTLS.CreateTLSConfig()
		if err != nil {
			test.Logf("Could not create CA certificate pool: %v", err)
			return false
		}
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			test.Logf("Could not connect to server (tls enabled): %v", err)
			return false
		}
		conn.Close()
	} else {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			test.Logf("Could not connect to server (tls disabled): %v", err)
			return false
		}
		conn.Close()
	}
	return true
}

func waitForServerUp(test *testing.T, application Applicationer, tlsEnabled bool) {
	maxWaitTime := 10 * time.Second
	startTime := time.Now()

	for {
		if time.Since(startTime) > maxWaitTime {
			test.Fatalf("Server didn't start within the specified time")
		}

		if isServerUp(test, application.GetGRPCServerAddress(), tlsEnabled) {
			test.Log("Server is up")
			break
		}

		time.Sleep(1 * time.Second)
	}
}

func startMockMongoServer(test *testing.T) *memongo.Server {
	memongoOptions := &memongo.Options{
		LogLevel:     10,
		MongoVersion: "4.0.5",
	}
	if runtime.GOARCH == "arm64" {
		if runtime.GOOS == "darwin" {
			// Only set the custom url as workaround for arm64 macs
			memongoOptions.DownloadURL = "https://fastdl.mongodb.org/osx/mongodb-macos-x86_64-5.0.0.tgz"
		}
	}
	mongoServer, err := memongo.StartWithOptions(memongoOptions)
	if err != nil {
		test.Fatalf("Failed to start mock mongo server: %v", err)
	}
	return mongoServer
}

// MockEmailServiceServer is a mock implementation of the EmailServiceServer
type MockEmailServiceServer struct {
	pb_email.UnimplementedEmailServiceServer
}

// SendEmail mocks the SendEmail method
func (m *MockEmailServiceServer) SendEmail(ctx context.Context, req *pb_email.SendEmailRequest) (*pb_email.SendEmailResponse, error) {
	if req.To == wrongEmail {
		return &pb_email.SendEmailResponse{Success: false, Message: "Email not sent"}, fmt.Errorf("Email not sent")
	}
	return &pb_email.SendEmailResponse{Success: true, Message: "Mocked email sent"}, nil
}

func startMockEmailServiceServer(t *testing.T, emailGRPCAddress string, tlsEnabled bool) (*grpc.Server, net.Listener) {
	const certFilePath = "certs/qd.email.api.crt"
	const keyFilePath = "certs/qd.email.api.key"

	listener, err := commonTLS.CreateTLSListener(emailGRPCAddress, certFilePath, keyFilePath, tlsEnabled)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	mockServer := grpc.NewServer()
	pb_email.RegisterEmailServiceServer(mockServer, &MockEmailServiceServer{})

	go func() {
		if err := mockServer.Serve(listener); err != nil {
			t.Errorf("mock server failed to serve: %v", err)
		}
	}()

	return mockServer, listener
}

func TestRegisterUserJourneys(t *testing.T) {
	email := "test@test.com"
	password := "Password123!"
	correlationID := "1234567890"
	dateOfBirth := timestamppb.New(time.Now().AddDate(-20, 0, 0))
	registerRequest := &pb_authentication.RegisterRequest{
		Email:       email,
		Password:    password,
		FirstName:   "John",
		LastName:    "Doe",
		DateOfBirth: dateOfBirth,
	}

	// Logs configurations
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Setenv(commonConfig.AppEnvironmentKey, "test")

	mongoServer := startMockMongoServer(t)
	defer mongoServer.Stop()

	// Save current working directory and change it
	originalWD, err := commonUtil.ChangeCurrentWorkingDirectory("../..")
	if err != nil {
		t.Fatalf("Failed to change working directory: %s", err)
	}
	// Defer the reset of the working directory
	defer os.Chdir(*originalWD)

	var config config.Config
	config.Load("internal/config")
	config.AuthenticationDB.URI = mongoServer.URI()
	centralConfig := commonConfig.Config{
		TLSEnabled:                true,
		EmailVerificationEndpoint: "http://localhost:2222/",
		EmailService: commonConfig.Address{
			Host: "qd.email.api",
			Port: "1111",
		},
		AuthenticationService: commonConfig.Address{
			Host: "qd.authentication.api",
			Port: "3333",
		},
	}

	mockEmailServer, _ := startMockEmailServiceServer(t, fmt.Sprintf(
		"%s:%s",
		centralConfig.EmailService.Host,
		centralConfig.EmailService.Port),
		centralConfig.TLSEnabled,
	)
	defer mockEmailServer.Stop()

	application := NewApplication(&config, &centralConfig)
	go func() {
		t.Log(fmt.Sprintf("Starting server on %s...\n", application.GetGRPCServerAddress()))
		application.StartServer()
	}()
	defer application.Close()

	waitForServerUp(t, application, centralConfig.TLSEnabled)

	t.Run("Get_Public_Key_Success", func(t *testing.T) {

		connection, err := commonTLS.CreateGRPCConnection(application.GetGRPCServerAddress(), centralConfig.TLSEnabled)
		assert.NoError(t, err)

		client := pb_authentication.NewAuthenticationServiceClient(connection)

		getPublicKeyResponse, err := client.GetPublicKey(
			commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID),
			&pb_authentication.GetPublicKeyRequest{},
		)

		assert.NoError(t, err)
		assert.NotNil(t, getPublicKeyResponse)
		assert.NotNil(t, getPublicKeyResponse.PublicKey)
		assert.Contains(t, getPublicKeyResponse.PublicKey, "BEGIN RSA PUBLIC KEY")
		assert.Contains(t, getPublicKeyResponse.PublicKey, "END RSA PUBLIC KEY")
	})

	t.Run("Register_Success", func(t *testing.T) {
		connection, err := commonTLS.CreateGRPCConnection(application.GetGRPCServerAddress(), centralConfig.TLSEnabled)
		assert.NoError(t, err)

		client := pb_authentication.NewAuthenticationServiceClient(connection)

		registerResponse, err := client.Register(
			commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID),
			registerRequest,
		)

		assert.NoError(t, err)
		assert.Equal(t, registerResponse.Success, true)
		assert.Equal(t, registerResponse.Message, "Registration successful")
	})

	t.Run("Register_Failure_Already_Existing_User", func(t *testing.T) {
		connection, err := commonTLS.CreateGRPCConnection(application.GetGRPCServerAddress(), centralConfig.TLSEnabled)
		assert.NoError(t, err)

		client := pb_authentication.NewAuthenticationServiceClient(connection)

		registerResponse, err := client.Register(
			commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID),
			registerRequest,
		)

		assert.Error(t, err)
		assert.Nil(t, registerResponse)
		assert.Equal(t, err.Error(), "rpc error: code = InvalidArgument desc = Registration failed: email already in use")
	})

	t.Run("Register_Failure_Send_Email_Error", func(t *testing.T) {
		connection, err := commonTLS.CreateGRPCConnection(application.GetGRPCServerAddress(), centralConfig.TLSEnabled)
		assert.NoError(t, err)

		client := pb_authentication.NewAuthenticationServiceClient(connection)

		registerResponse, err := client.Register(
			commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID),
			&pb_authentication.RegisterRequest{
				Email:       wrongEmail,
				Password:    password,
				FirstName:   "John",
				LastName:    "Doe",
				DateOfBirth: dateOfBirth,
			})

		assert.NoError(t, err)
		assert.Equal(t, "Registration successful. However, verification email failed to send", registerResponse.Message)
		assert.Equal(t, registerResponse.Success, true)
	})

	t.Run("Verify_Email_Error_Wrong_Token", func(t *testing.T) {
		connection, err := commonTLS.CreateGRPCConnection(application.GetGRPCServerAddress(), centralConfig.TLSEnabled)
		assert.NoError(t, err)

		client := pb_authentication.NewAuthenticationServiceClient(connection)
		registerResponse, err := client.VerifyEmail(
			commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID),
			&pb_authentication.VerifyEmailRequest{
				VerificationToken: "1234567890",
			})

		assert.Error(t, err)
		assert.Nil(t, registerResponse)
		assert.Equal(t, err.Error(), "rpc error: code = InvalidArgument desc = Invalid verification token")
	})

	t.Run("Authenticate_Success", func(t *testing.T) {
		client, err := mongo.NewClient(options.Client().ApplyURI(mongoServer.URI()))
		if err != nil {
			log.Err(err)
		}

		ctx := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		err = client.Connect(ctx)
		if err != nil {
			log.Err(err)
		}
		defer client.Disconnect(ctx)

		collection := client.Database("qd_authentication").Collection("user")
		var foundUser model.User
		err = collection.FindOne(ctx, bson.M{"email": email}).Decode(&foundUser)
		if err != nil {
			log.Err(err)
		}

		connection, err := commonTLS.CreateGRPCConnection(application.GetGRPCServerAddress(), centralConfig.TLSEnabled)
		assert.NoError(t, err)

		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)

		registerResponse, err := grpcClient.Authenticate(ctx, &pb_authentication.AuthenticateRequest{
			Email:    foundUser.Email,
			Password: password,
		})

		jwtToken = registerResponse.AuthToken
		assert.NoError(t, err)
		assert.NotNil(t, registerResponse)
		assert.NotNil(t, registerResponse.AuthToken)
		assert.NotNil(t, registerResponse.RefreshToken)
		assert.Equal(t, foundUser.Email, registerResponse.UserEmail)
	})

	t.Run("ResendVerificationEmail_Success", func(t *testing.T) {
		client, err := mongo.NewClient(options.Client().ApplyURI(mongoServer.URI()))
		if err != nil {
			log.Err(err)
		}

		ctx := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		err = client.Connect(ctx)
		if err != nil {
			log.Err(err)
		}
		defer client.Disconnect(ctx)

		collection := client.Database("qd_authentication").Collection("user")
		var foundUser model.User
		err = collection.FindOne(ctx, bson.M{"email": email}).Decode(&foundUser)
		if err != nil {
			log.Err(err)
		}

		connection, err := commonTLS.CreateGRPCConnection(application.GetGRPCServerAddress(), centralConfig.TLSEnabled)
		assert.NoError(t, err)

		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)

		resendEamilVerificationResponse, err := grpcClient.ResendEmailVerification(ctx, &pb_authentication.ResendEmailVerificationRequest{
			AuthToken: jwtToken,
		})

		assert.NoError(t, err)
		assert.NotNil(t, resendEamilVerificationResponse)
		assert.Equal(t, resendEamilVerificationResponse.Success, true)
		assert.Equal(t, resendEamilVerificationResponse.Message, "Email verification sent successfully")
	})

	t.Run("ResendVerificationEmail_JWT_Error", func(t *testing.T) {
		client, err := mongo.NewClient(options.Client().ApplyURI(mongoServer.URI()))
		if err != nil {
			log.Err(err)
		}

		ctx := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		err = client.Connect(ctx)
		if err != nil {
			log.Err(err)
		}
		defer client.Disconnect(ctx)

		connection, err := commonTLS.CreateGRPCConnection(application.GetGRPCServerAddress(), centralConfig.TLSEnabled)
		assert.NoError(t, err)

		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)

		resendEamilVerificationResponse, err := grpcClient.ResendEmailVerification(
			ctx,
			&pb_authentication.ResendEmailVerificationRequest{
				AuthToken: "jwtToken",
			},
		)

		assert.Error(t, err)
		assert.Nil(t, resendEamilVerificationResponse)
		assert.Equal(t, "rpc error: code = Unauthenticated desc = Invalid JWT token", err.Error())
	})

	t.Run("Verify_Email_Success", func(t *testing.T) {
		client, err := mongo.NewClient(options.Client().ApplyURI(mongoServer.URI()))
		if err != nil {
			log.Err(err)
		}
		ctx := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)

		err = client.Connect(ctx)
		if err != nil {
			log.Err(err)
		}
		defer client.Disconnect(ctx)

		collection := client.Database("qd_authentication").Collection("user")
		var foundUser model.User
		err = collection.FindOne(ctx, bson.M{"email": email}).Decode(&foundUser)
		if err != nil {
			log.Err(err)
		}

		connection, err := commonTLS.CreateGRPCConnection(application.GetGRPCServerAddress(), centralConfig.TLSEnabled)
		assert.NoError(t, err)

		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)

		registerResponse, err := grpcClient.VerifyEmail(ctx, &pb_authentication.VerifyEmailRequest{
			VerificationToken: foundUser.VerificationToken,
		})

		assert.NoError(t, err)
		assert.NotNil(t, registerResponse)
		assert.Equal(t, registerResponse.Message, "Email verified successfully")
		assert.Equal(t, registerResponse.Success, true)
	})

	t.Run("Authenticate_Error", func(t *testing.T) {
		client, err := mongo.NewClient(options.Client().ApplyURI(mongoServer.URI()))
		if err != nil {
			log.Err(err)
		}
		ctx := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		err = client.Connect(ctx)
		if err != nil {
			log.Err(err)
		}
		defer client.Disconnect(ctx)

		collection := client.Database("qd_authentication").Collection("user")
		var foundUser model.User
		err = collection.FindOne(ctx, bson.M{"email": email}).Decode(&foundUser)
		if err != nil {
			log.Err(err)
		}

		connection, err := commonTLS.CreateGRPCConnection(application.GetGRPCServerAddress(), centralConfig.TLSEnabled)
		assert.NoError(t, err)

		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)

		registerResponse, err := grpcClient.Authenticate(ctx, &pb_authentication.AuthenticateRequest{
			Email:    foundUser.Email,
			Password: "password",
		})

		assert.Error(t, err)
		assert.Nil(t, registerResponse)
		assert.Equal(t, "rpc error: code = Unauthenticated desc = Invalid email or password", err.Error())
	})
}

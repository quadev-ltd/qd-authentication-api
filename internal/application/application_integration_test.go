package application

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	pkgConfig "github.com/gustavo-m-franco/qd-common/pkg/config"
	pkgLog "github.com/gustavo-m-franco/qd-common/pkg/log"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/tryvium-travels/memongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/grpc"

	"qd-authentication-api/internal/config"
	"qd-authentication-api/internal/model"
	"qd-authentication-api/pb/gen/go/pb_authentication"
	"qd-authentication-api/pb/gen/go/pb_email"
)

func isServerUp(addr string) bool {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func waitForServerUp(test *testing.T, application Applicationer) {
	maxWaitTime := 10 * time.Second
	startTime := time.Now()

	for {
		if time.Since(startTime) > maxWaitTime {
			test.Fatalf("Server didn't start within the specified time")
		}

		if isServerUp(application.GetGRPCServerAddress()) {
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

const wrongEmail = "wrong@email.com"

// SendEmail mocks the SendEmail method
func (m *MockEmailServiceServer) SendEmail(ctx context.Context, req *pb_email.SendEmailRequest) (*pb_email.SendEmailResponse, error) {
	if req.To == wrongEmail {
		return &pb_email.SendEmailResponse{Success: false, Message: "Email not sent"}, fmt.Errorf("Email not sent")
	}
	return &pb_email.SendEmailResponse{Success: true, Message: "Mocked email sent"}, nil
}

func startMockEmailServiceServer(t *testing.T, emailGRPCAddress string) (*grpc.Server, net.Listener) {
	lis, err := net.Listen("tcp", emailGRPCAddress)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	mockServer := grpc.NewServer()
	pb_email.RegisterEmailServiceServer(mockServer, &MockEmailServiceServer{})

	go func() {
		if err := mockServer.Serve(lis); err != nil {
			t.Errorf("mock server failed to serve: %v", err)
		}
	}()

	return mockServer, lis
}

var jwtToken string

func TestRegisterUserJourneys(t *testing.T) {
	email := "test@test.com"
	password := "Password123!"
	correlationID := "1234567890"

	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Setenv(pkgConfig.AppEnvironmentKey, "test")

	mongoServer := startMockMongoServer(t)
	defer mongoServer.Stop()

	var config config.Config
	config.Load("../../internal/config")
	config.DB.URI = mongoServer.URI()

	mockEmailServer, _ := startMockEmailServiceServer(t, fmt.Sprintf("%s:%s", config.Email.Host, config.Email.Port))
	defer mockEmailServer.Stop()

	application := NewApplication(&config)
	go func() {
		application.StartServer()
	}()
	defer application.Close()

	waitForServerUp(t, application)

	t.Run("Get_Public_Key_Success", func(t *testing.T) {

		connection, err := grpc.Dial(application.GetGRPCServerAddress(), grpc.WithInsecure())
		assert.NoError(t, err)

		client := pb_authentication.NewAuthenticationServiceClient(connection)

		getPublicKeyResponse, err := client.GetPublicKey(
			pkgLog.AddCorrelationIDToContext(context.Background(), correlationID),
			&pb_authentication.GetPublicKeyRequest{},
		)

		assert.NoError(t, err)
		assert.NotNil(t, getPublicKeyResponse)
		assert.NotNil(t, getPublicKeyResponse.PublicKey)
		assert.Contains(t, getPublicKeyResponse.PublicKey, "BEGIN RSA PUBLIC KEY")
		assert.Contains(t, getPublicKeyResponse.PublicKey, "END RSA PUBLIC KEY")
	})

	t.Run("Register_Success", func(t *testing.T) {
		connection, err := grpc.Dial(application.GetGRPCServerAddress(), grpc.WithInsecure())
		assert.NoError(t, err)

		client := pb_authentication.NewAuthenticationServiceClient(connection)

		registerResponse, err := client.Register(
			pkgLog.AddCorrelationIDToContext(context.Background(), correlationID),
			&pb_authentication.RegisterRequest{
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

		registerResponse, err := client.Register(
			pkgLog.AddCorrelationIDToContext(context.Background(), correlationID),
			&pb_authentication.RegisterRequest{
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

	t.Run("Register_Failure_Send_Email_Error", func(t *testing.T) {
		connection, err := grpc.Dial(application.GetGRPCServerAddress(), grpc.WithInsecure())
		assert.NoError(t, err)

		client := pb_authentication.NewAuthenticationServiceClient(connection)

		registerResponse, err := client.Register(
			pkgLog.AddCorrelationIDToContext(context.Background(), correlationID),
			&pb_authentication.RegisterRequest{
				Email:     wrongEmail,
				Password:  password,
				FirstName: "John",
				LastName:  "Doe",
				// Populate other fields as needed
			})

		assert.NoError(t, err)
		assert.Equal(t, "Registration successful. However, verification email failed to send", registerResponse.Message)
		assert.Equal(t, registerResponse.Success, true)
	})

	t.Run("Verify_Email_Error_Wrong_Token", func(t *testing.T) {
		connection, err := grpc.Dial(application.GetGRPCServerAddress(), grpc.WithInsecure())
		assert.NoError(t, err)

		client := pb_authentication.NewAuthenticationServiceClient(connection)
		registerResponse, err := client.VerifyEmail(
			pkgLog.AddCorrelationIDToContext(context.Background(), correlationID),
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

		ctx := pkgLog.AddCorrelationIDToContext(context.Background(), correlationID)
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

		connection, err := grpc.Dial(application.GetGRPCServerAddress(), grpc.WithInsecure())
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

		ctx := pkgLog.AddCorrelationIDToContext(context.Background(), correlationID)
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

		connection, err := grpc.Dial(application.GetGRPCServerAddress(), grpc.WithInsecure())
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

		ctx := pkgLog.AddCorrelationIDToContext(context.Background(), correlationID)
		err = client.Connect(ctx)
		if err != nil {
			log.Err(err)
		}
		defer client.Disconnect(ctx)

		connection, err := grpc.Dial(application.GetGRPCServerAddress(), grpc.WithInsecure())
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
		ctx := pkgLog.AddCorrelationIDToContext(context.Background(), correlationID)

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

		connection, err := grpc.Dial(application.GetGRPCServerAddress(), grpc.WithInsecure())
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
		ctx := pkgLog.AddCorrelationIDToContext(context.Background(), correlationID)
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

		connection, err := grpc.Dial(application.GetGRPCServerAddress(), grpc.WithInsecure())
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

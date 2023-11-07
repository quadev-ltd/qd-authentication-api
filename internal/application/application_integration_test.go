package application

import (
	"context"
	"fmt"
	"net"
	"os"
	"qd-authentication-api/internal/config"
	"qd-authentication-api/internal/model"
	"qd-authentication-api/pb/gen/go/pb_authentication"
	"runtime"
	"testing"
	"time"

	pkgConfig "github.com/gustavo-m-franco/qd-common/pkg/config"
	pkgLogger "github.com/gustavo-m-franco/qd-common/pkg/log"

	"github.com/mhale/smtpd"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/tryvium-travels/memongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
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
			log.Error().Msg("Server didn't start within the specified time")
		}

		if isServerUp(application.GetGRPCServerAddress()) {
			log.Error().Msg("Server is up")
			break
		}

		time.Sleep(1 * time.Second)
	}
}

func startMockMongoServer() (*memongo.Server, error) {
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
		return nil, err
	}
	return mongoServer, nil
}

func startMockSMTPServer(mockSMTPServerHost string, mockSMTPServerPort string) *smtpd.Server {
	authMechanisms := map[string]bool{
		"PLAIN": true,
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
		log.Info().Msg(fmt.Sprintf("Starting mock SMTP server %s... ", fmt.Sprintf("%s:%s", mockSMTPServerHost, mockSMTPServerPort)))
		err := smtpServer.ListenAndServe()
		if err != nil {
			log.Err(err)
		}
	}()
	return &smtpServer
}

func contextWithCorrelationID(correlationID string) context.Context {
	md := metadata.New(map[string]string{
		pkgLogger.CorrelationIDKey: correlationID,
	})
	ctx := metadata.NewOutgoingContext(context.Background(), md)
	return ctx
}

var jwtToken string

func TestRegisterUserJourneys(t *testing.T) {
	email := "test@test.com"
	password := "test123"
	correlationID := "1234567890"

	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Setenv(pkgConfig.AppEnvironmentKey, "test")

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
		application.StartServer()
	}()
	defer application.Close()

	waitForServerUp(application)

	t.Run("Get_Public_Key_Success", func(t *testing.T) {

		connection, err := grpc.Dial(application.GetGRPCServerAddress(), grpc.WithInsecure())
		assert.NoError(t, err)

		client := pb_authentication.NewAuthenticationServiceClient(connection)

		getPublicKeyResponse, err := client.GetPublicKey(
			contextWithCorrelationID(correlationID),
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
			contextWithCorrelationID(correlationID),
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
			contextWithCorrelationID(correlationID),
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

	t.Run("Verify_Email_Error_Wrong_Token", func(t *testing.T) {
		connection, err := grpc.Dial(application.GetGRPCServerAddress(), grpc.WithInsecure())
		assert.NoError(t, err)

		client := pb_authentication.NewAuthenticationServiceClient(connection)
		registerResponse, err := client.VerifyEmail(
			contextWithCorrelationID(correlationID),
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

		ctx := contextWithCorrelationID(correlationID)
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

		ctx := contextWithCorrelationID(correlationID)

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

		ctx := contextWithCorrelationID(correlationID)
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
		ctx := contextWithCorrelationID(correlationID)

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
		ctx := contextWithCorrelationID(correlationID)
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

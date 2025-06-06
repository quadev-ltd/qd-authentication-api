package application

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"regexp"
	"testing"
	"time"

	"firebase.google.com/go/auth"
	"github.com/golang/mock/gomock"
	"github.com/quadev-ltd/qd-common/pb/gen/go/pb_authentication"
	"github.com/quadev-ltd/qd-common/pb/gen/go/pb_email"
	commonConfig "github.com/quadev-ltd/qd-common/pkg/config"
	commonJWT "github.com/quadev-ltd/qd-common/pkg/jwt"
	commonLogger "github.com/quadev-ltd/qd-common/pkg/log"
	commonPB "github.com/quadev-ltd/qd-common/pkg/pb"
	commonTLS "github.com/quadev-ltd/qd-common/pkg/tls"
	commonUtil "github.com/quadev-ltd/qd-common/pkg/util"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/tryvium-travels/memongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"qd-authentication-api/internal/config"
	"qd-authentication-api/internal/dto"
	firebaseMock "qd-authentication-api/internal/firebase/mock"
	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/mongo/mock"
	"qd-authentication-api/internal/util"
)

const wrongEmail = "wrong@email.com"

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

// MockEmailServiceServer is a mock implementation of the EmailServiceServer
type MockEmailServiceServer struct {
	pb_email.UnimplementedEmailServiceServer
	LastCapturedEmailVerificationToken string
	LastCapturedPasswordResetToken     string
}

// SendEmail mocks the SendEmail method
func (m *MockEmailServiceServer) SendEmail(ctx context.Context, req *pb_email.SendEmailRequest) (*pb_email.SendEmailResponse, error) {
	if req.To == wrongEmail {
		return &pb_email.SendEmailResponse{Success: false, Message: "Email not sent"}, fmt.Errorf("Email not sent")
	}
	pattern := `/user/.*/email/(.*)" class="button">Verify your email</a>`
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(req.Body)

	if len(matches) > 1 {
		m.LastCapturedEmailVerificationToken = matches[1]
	}

	pattern = `/user/.*/password/reset/(.*)" class="button">Reset password</a>`
	re = regexp.MustCompile(pattern)
	matches = re.FindStringSubmatch(req.Body)

	if len(matches) > 1 {
		m.LastCapturedPasswordResetToken = matches[1]
	}

	return &pb_email.SendEmailResponse{Success: true, Message: "Mocked email sent"}, nil
}

func startMockEmailServiceServer(t *testing.T, emailGRPCAddress string, tlsEnabled bool) (*grpc.Server, net.Listener, *MockEmailServiceServer) {
	const certFilePath = "certs/qd.email.api.crt"
	const keyFilePath = "certs/qd.email.api.key"

	listener, err := commonTLS.CreateTLSListener(emailGRPCAddress, certFilePath, keyFilePath, tlsEnabled)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	mockServer := grpc.NewServer()
	mockEmailService := &MockEmailServiceServer{}
	pb_email.RegisterEmailServiceServer(mockServer, mockEmailService)

	go func() {
		if err := mockServer.Serve(listener); err != nil {
			t.Errorf("mock server failed to serve: %v", err)
		}
	}()

	return mockServer, listener, mockEmailService
}

type EnvironmentParams struct {
	MockFirebaseService *firebaseMock.MockAuthServicer
	MockMongoServer     *memongo.Server
	MockConfig          *commonConfig.Config
	Application         Applicationer
	Controller          *gomock.Controller
}

var mockCentralConfig = commonConfig.Config{
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

func setUpTestEnvironment(t *testing.T) *EnvironmentParams {
	mongoServer := mock.SetUpMongoServer(t)

	var config config.Config
	config.Load("internal/config")
	config.AuthenticationDB.URI = mongoServer.URI()

	controller := gomock.NewController(t)
	mockFirebaseService := firebaseMock.NewMockAuthServicer(controller)

	application := NewApplication(&config, &mockCentralConfig, mockFirebaseService)
	go func() {
		t.Logf("Starting server on %s...\n", application.GetGRPCServerAddress())
		application.StartServer()
	}()

	waitForServerUp(t, application, mockCentralConfig.TLSEnabled)

	return &EnvironmentParams{
		MockFirebaseService: mockFirebaseService,
		MockMongoServer:     mongoServer,
		MockConfig:          &mockCentralConfig,
		Application:         application,
		Controller:          controller,
	}
}

func TestRegisterUserJourneys(t *testing.T) {
	// Save current working directory and change it to be in the root folder of the project
	originalWD, err := commonUtil.ChangeCurrentWorkingDirectory("../..")
	if err != nil {
		t.Fatalf("Failed to change working directory: %s", err)
	}
	// Defer the reset of the working directory
	defer os.Chdir(*originalWD)
	// Set mock email server
	mockEmailServer, _, mockEmailService := startMockEmailServiceServer(t, fmt.Sprintf(
		"%s:%s",
		mockCentralConfig.EmailService.Host,
		mockCentralConfig.EmailService.Port),
		mockCentralConfig.TLSEnabled,
	)
	defer mockEmailServer.Stop()

	// Logs configurations
	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	os.Setenv(commonConfig.AppEnvironmentKey, "test")

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

	tokenInspector := &commonJWT.TokenInspector{}

	t.Run("Get_Public_Key_Success", func(t *testing.T) {
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()
		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
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

	t.Run("UnauthenticatedRequestsError", func(t *testing.T) {
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()
		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
		assert.NoError(t, err)

		client := pb_authentication.NewAuthenticationServiceClient(connection)
		ctxWithCorrelationID := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		_, err = client.RefreshToken(
			ctxWithCorrelationID,
			&pb_authentication.RefreshTokenRequest{},
		)

		assert.Error(t, err)
		assert.EqualError(t, err, "rpc error: code = Unauthenticated desc = Authorization token not provided")

		_, err = client.GetUserProfile(
			ctxWithCorrelationID,
			&pb_authentication.GetUserProfileRequest{},
		)

		assert.Error(t, err)
		assert.EqualError(t, err, "rpc error: code = Unauthenticated desc = Authorization token not provided")

		_, err = client.UpdateUserProfile(
			ctxWithCorrelationID,
			&pb_authentication.UpdateUserProfileRequest{},
		)

		assert.Error(t, err)
		assert.EqualError(t, err, "rpc error: code = Unauthenticated desc = Authorization token not provided")
	})

	t.Run("Register_Success", func(t *testing.T) {
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()
		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
		assert.NoError(t, err)

		client := pb_authentication.NewAuthenticationServiceClient(connection)

		registerResponse, err := client.Register(
			commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID),
			registerRequest,
		)

		assert.NoError(t, err)
		assert.Equal(t, registerResponse.Success, true)
		assert.Equal(t, registerResponse.Message, "Registration successful")
		assert.NotNil(t, registerResponse.User.UserID)
		assert.Equal(t, registerResponse.User.Email, registerRequest.Email)
		assert.Equal(t, registerResponse.User.FirstName, registerRequest.FirstName)
		assert.Equal(t, registerResponse.User.LastName, registerRequest.LastName)
	})

	t.Run("Register_Failure_Already_Existing_User", func(t *testing.T) {
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()
		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
		assert.NoError(t, err)

		client := pb_authentication.NewAuthenticationServiceClient(connection)

		registerResponse, err := client.Register(
			commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID),
			registerRequest,
		)

		assert.NoError(t, err)
		assert.Equal(t, registerResponse.Success, true)
		assert.Equal(t, registerResponse.Message, "Registration successful")

		registerResponse, err = client.Register(
			commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID),
			registerRequest,
		)

		assert.Error(t, err)
		assert.Nil(t, registerResponse)
		assert.Equal(t, err.Error(), "rpc error: code = InvalidArgument desc = Registration failed")
		fieldErrors, err := commonPB.GetFieldValidationErrors(err)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, fieldErrors[0].Field, "email")
		assert.Equal(t, fieldErrors[0].Error, "already_used")

	})

	t.Run("Register_Failure_Send_Email_Error", func(t *testing.T) {
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()
		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
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
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()
		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
		assert.NoError(t, err)

		client := pb_authentication.NewAuthenticationServiceClient(connection)
		verifyEmailResponse, err := client.VerifyEmail(
			commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID),
			&pb_authentication.VerifyEmailRequest{
				VerificationToken: "1234567890",
				UserID:            primitive.NewObjectID().Hex(),
			})

		assert.Error(t, err)
		assert.Nil(t, verifyEmailResponse)
		assert.Equal(t, "rpc error: code = InvalidArgument desc = invalid_token", err.Error())
	})

	t.Run("Authenticate_Success", func(t *testing.T) {
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()
		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
		assert.NoError(t, err)
		client, err := mongo.NewClient(options.Client().ApplyURI(envParams.MockMongoServer.URI()))
		if err != nil {
			t.Fatal(err)
		}

		ctxWithCorrelationID := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)
		_, err = grpcClient.Register(
			ctxWithCorrelationID,
			registerRequest,
		)
		if err != nil {
			t.Fatal(err)
		}

		// Get registered user
		err = client.Connect(ctxWithCorrelationID)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Disconnect(ctxWithCorrelationID)

		collection := client.Database("qd_authentication").Collection("user")
		var foundUser model.User
		err = collection.FindOne(ctxWithCorrelationID, bson.M{"email": email}).Decode(&foundUser)
		if err != nil {
			t.Fatal(err)
		}

		testFirebaseToken := "test-firebase-token"
		envParams.MockFirebaseService.EXPECT().CreateCustomToken(
			gomock.Any(),
			foundUser.ID.Hex(),
		).Return(
			testFirebaseToken,
			nil,
		)

		authenticateResponse, err := grpcClient.Authenticate(ctxWithCorrelationID, &pb_authentication.AuthenticateRequest{
			Email:    foundUser.Email,
			Password: password,
		})

		assert.NoError(t, err)
		assert.NotNil(t, authenticateResponse)
		assert.NotNil(t, authenticateResponse.AuthToken)
		assert.NotNil(t, authenticateResponse.RefreshToken)
		assert.Equal(t, testFirebaseToken, authenticateResponse.FirebaseToken, "Firebase token should be included in the response")
	})

	t.Run("AuthenticateWithFirebase_Success", func(t *testing.T) {
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()
		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
		assert.NoError(t, err)
		client, err := mongo.NewClient(options.Client().ApplyURI(envParams.MockMongoServer.URI()))
		if err != nil {
			t.Fatal(err)
		}

		ctxWithCorrelationID := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)
		_, err = grpcClient.Register(
			ctxWithCorrelationID,
			registerRequest,
		)
		if err != nil {
			t.Fatal(err)
		}

		// Get registered user
		err = client.Connect(ctxWithCorrelationID)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Disconnect(ctxWithCorrelationID)

		collection := client.Database("qd_authentication").Collection("user")
		var foundUser model.User
		err = collection.FindOne(ctxWithCorrelationID, bson.M{"email": email}).Decode(&foundUser)
		if err != nil {
			t.Fatal(err)
		}

		testIDToken := "test-id-token"
		token := &auth.Token{
			Claims: map[string]interface{}{
				"email": foundUser.Email,
			},
		}
		envParams.MockFirebaseService.EXPECT().VerifyIDToken(
			gomock.Any(),
			testIDToken,
		).Return(token, nil)
		authenticateResponse, err := grpcClient.AuthenticateWithFirebase(
			ctxWithCorrelationID,
			&pb_authentication.AuthenticateWithFirebaseRequest{
				Email:   foundUser.Email,
				IdToken: testIDToken,
			},
		)

		assert.NoError(t, err)
		assert.NotNil(t, authenticateResponse)
		assert.NotNil(t, authenticateResponse.AuthToken)
		assert.NotNil(t, authenticateResponse.RefreshToken)

		err = collection.FindOne(ctxWithCorrelationID, bson.M{"email": email}).Decode(&foundUser)
		if err != nil {
			t.Fatal(err)
		}

		assert.True(t, model.ContainsAuthType(foundUser.AuthTypes, model.FirebaseAuthType))
		assert.True(t, model.ContainsAuthType(foundUser.AuthTypes, model.PasswordAuthType))
	})

	t.Run("AuthenticateWithFirebase_NonExistentUser_Success", func(t *testing.T) {
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()
		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
		assert.NoError(t, err)

		ctxWithCorrelationID := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)

		testIDToken := "test-id-token"
		firstName := "first-name"
		lastName := "last-name"
		token := &auth.Token{
			Claims: map[string]interface{}{
				"email": email,
			},
		}
		envParams.MockFirebaseService.EXPECT().VerifyIDToken(
			gomock.Any(),
			testIDToken,
		).Return(token, nil)
		authenticateResponse, err := grpcClient.AuthenticateWithFirebase(
			ctxWithCorrelationID,
			&pb_authentication.AuthenticateWithFirebaseRequest{
				Email:     email,
				FirstName: firstName,
				LastName:  lastName,
				IdToken:   testIDToken,
			},
		)

		assert.NoError(t, err)
		assert.NotNil(t, authenticateResponse)
		assert.NotNil(t, authenticateResponse.AuthToken)
		assert.NotNil(t, authenticateResponse.RefreshToken)

		client, err := mongo.NewClient(options.Client().ApplyURI(envParams.MockMongoServer.URI()))
		if err != nil {
			t.Fatal(err)
		}

		// Get registered user
		err = client.Connect(ctxWithCorrelationID)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Disconnect(ctxWithCorrelationID)

		collection := client.Database("qd_authentication").Collection("user")
		var foundUser model.User
		err = collection.FindOne(ctxWithCorrelationID, bson.M{"email": email}).Decode(&foundUser)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, firstName, foundUser.FirstName)
		assert.Equal(t, lastName, foundUser.LastName)
		assert.True(t, model.ContainsAuthType(foundUser.AuthTypes, model.FirebaseAuthType))
		assert.False(t, model.ContainsAuthType(foundUser.AuthTypes, model.PasswordAuthType))
	})

	t.Run("Authenticate_UpdateAndGetUserProfile_Success", func(t *testing.T) {
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()
		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
		assert.NoError(t, err)
		client, err := mongo.NewClient(options.Client().ApplyURI(envParams.MockMongoServer.URI()))
		if err != nil {
			t.Fatal(err)
		}

		ctxWithCorrelationID := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)

		_, err = grpcClient.Register(
			ctxWithCorrelationID,
			registerRequest,
		)
		if err != nil {
			t.Fatal(err)
		}

		// Get registered user
		err = client.Connect(ctxWithCorrelationID)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Disconnect(ctxWithCorrelationID)

		collection := client.Database("qd_authentication").Collection("user")
		var foundUser model.User
		err = collection.FindOne(ctxWithCorrelationID, bson.M{"email": email}).Decode(&foundUser)
		if err != nil {
			t.Fatal(err)
		}

		testFirebaseToken := "test-firebase-token"
		envParams.MockFirebaseService.EXPECT().CreateCustomToken(
			gomock.Any(),
			foundUser.ID.Hex(),
		).Return(
			testFirebaseToken,
			nil,
		)

		authenticateResponse, err := grpcClient.Authenticate(ctxWithCorrelationID, &pb_authentication.AuthenticateRequest{
			Email:    foundUser.Email,
			Password: password,
		})
		if err != nil {
			t.Fatal(err)
		}

		authCtx := commonJWT.AddAuthorizationMetadataToContext(ctxWithCorrelationID, authenticateResponse.AuthToken)

		profileResponse, err := grpcClient.GetUserProfile(
			authCtx,
			&pb_authentication.GetUserProfileRequest{},
		)
		if err != nil {
			t.Fatal(err)
		}

		assert.NoError(t, err)
		assert.NotNil(t, authenticateResponse)
		assert.Equal(t, foundUser.Email, profileResponse.User.Email)
		assert.Equal(t, foundUser.ID.Hex(), profileResponse.User.UserID)
		assert.Equal(t, dto.GetAccountStatusDescription(foundUser.AccountStatus), profileResponse.User.AccountStatus)
		assert.Equal(t, foundUser.FirstName, profileResponse.User.FirstName)
		assert.Equal(t, foundUser.LastName, profileResponse.User.LastName)
		assert.Equal(t, util.ConvertToTimestamp(foundUser.DateOfBirth).Nanos, profileResponse.User.DateOfBirth.Nanos)
		assert.Equal(t, util.ConvertToTimestamp(foundUser.DateOfBirth).Seconds, profileResponse.User.DateOfBirth.Seconds)
		assert.Equal(t, util.ConvertToTimestamp(foundUser.RegistrationDate).Nanos, profileResponse.User.RegistrationDate.Nanos)
		assert.Equal(t, util.ConvertToTimestamp(foundUser.RegistrationDate).Seconds, profileResponse.User.RegistrationDate.Seconds)

		newFirstName := "John"
		newLastName := "Doe"
		newDOB := timestamppb.Now()
		updateProfileResponse, err := grpcClient.UpdateUserProfile(
			authCtx,
			&pb_authentication.UpdateUserProfileRequest{
				FirstName:   newFirstName,
				LastName:    newLastName,
				DateOfBirth: newDOB,
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		assert.NoError(t, err)
		assert.NotNil(t, authenticateResponse)
		assert.Equal(t, foundUser.Email, updateProfileResponse.User.Email)
		assert.Equal(t, foundUser.ID.Hex(), updateProfileResponse.User.UserID)
		assert.Equal(t, dto.GetAccountStatusDescription(foundUser.AccountStatus), updateProfileResponse.User.AccountStatus)
		assert.Equal(t, newFirstName, updateProfileResponse.User.FirstName)
		assert.Equal(t, newLastName, updateProfileResponse.User.LastName)
		// assert.Equal(t, newDOB.Nanos, updateProfileResponse.User.DateOfBirth.Nanos)
		assert.Equal(t, newDOB.Seconds, updateProfileResponse.User.DateOfBirth.Seconds)

		profileResponse, err = grpcClient.GetUserProfile(
			authCtx,
			&pb_authentication.GetUserProfileRequest{},
		)
		if err != nil {
			t.Fatal(err)
		}

		assert.NoError(t, err)
		assert.NotNil(t, authenticateResponse)
		assert.Equal(t, foundUser.Email, profileResponse.User.Email)
		assert.Equal(t, foundUser.ID.Hex(), profileResponse.User.UserID)
		assert.Equal(t, dto.GetAccountStatusDescription(foundUser.AccountStatus), profileResponse.User.AccountStatus)
		assert.Equal(t, newFirstName, profileResponse.User.FirstName)
		assert.Equal(t, newLastName, profileResponse.User.LastName)
		// assert.Equal(t, newDOB.Nanos, profileResponse.User.DateOfBirth.Nanos)
		assert.Equal(t, newDOB.Seconds, profileResponse.User.DateOfBirth.Seconds)
	})

	t.Run("Authenticate_Error", func(t *testing.T) {
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()
		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
		assert.NoError(t, err)
		client, err := mongo.NewClient(options.Client().ApplyURI(envParams.MockMongoServer.URI()))
		if err != nil {
			t.Fatal(err)
		}

		ctxWithCorrelationID := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)
		_, err = grpcClient.Register(
			ctxWithCorrelationID,
			registerRequest,
		)
		if err != nil {
			t.Fatal(err)
		}

		// Get registered user
		err = client.Connect(ctxWithCorrelationID)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Disconnect(ctxWithCorrelationID)

		collection := client.Database("qd_authentication").Collection("user")
		var foundUser model.User
		err = collection.FindOne(ctxWithCorrelationID, bson.M{"email": email}).Decode(&foundUser)
		if err != nil {
			t.Fatal(err)
		}

		authenticateResponse, err := grpcClient.Authenticate(ctxWithCorrelationID, &pb_authentication.AuthenticateRequest{
			Email:    foundUser.Email,
			Password: "password",
		})

		assert.Error(t, err)
		assert.Nil(t, authenticateResponse)
		assert.Equal(t, "rpc error: code = Unauthenticated desc = invalid_email_password", err.Error())
	})

	t.Run("ResendVerificationEmail_Success", func(t *testing.T) {
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()
		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
		assert.NoError(t, err)
		client, err := mongo.NewClient(options.Client().ApplyURI(envParams.MockMongoServer.URI()))
		if err != nil {
			t.Fatal(err)
		}

		ctxWithCorrelationID := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)
		_, err = grpcClient.Register(
			ctxWithCorrelationID,
			registerRequest,
		)
		if err != nil {
			t.Fatal(err)
		}

		// Get registered user
		err = client.Connect(ctxWithCorrelationID)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Disconnect(ctxWithCorrelationID)

		collection := client.Database("qd_authentication").Collection("user")
		var foundUser model.User
		err = collection.FindOne(ctxWithCorrelationID, bson.M{"email": email}).Decode(&foundUser)
		if err != nil {
			t.Fatal(err)
		}

		testFirebaseToken := "test-firebase-token"
		envParams.MockFirebaseService.EXPECT().CreateCustomToken(
			gomock.Any(),
			foundUser.ID.Hex(),
		).Return(
			testFirebaseToken,
			nil,
		)
		authenticateResponse, err := grpcClient.Authenticate(ctxWithCorrelationID, &pb_authentication.AuthenticateRequest{
			Email:    foundUser.Email,
			Password: password,
		})
		if err != nil {
			t.Fatal(err)
		}

		authCtx := commonJWT.AddAuthorizationMetadataToContext(ctxWithCorrelationID, authenticateResponse.AuthToken)

		claims, err := tokenInspector.GetClaimsFromTokenString(authenticateResponse.AuthToken)
		if err != nil {
			t.Fatal(err)
		}

		resendEamilVerificationResponse, err := grpcClient.ResendEmailVerification(
			authCtx,
			&pb_authentication.ResendEmailVerificationRequest{
				UserID: claims.UserID,
			},
		)

		assert.NoError(t, err)
		assert.NotNil(t, resendEamilVerificationResponse)
		assert.Equal(t, resendEamilVerificationResponse.Success, true)
		assert.Equal(t, resendEamilVerificationResponse.Message, "Email verification sent successfully")
	})

	t.Run("ResendVerificationEmail_UserID_Error", func(t *testing.T) {
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()
		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
		assert.NoError(t, err)

		ctxWithCorrelationID := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		ctxAuth := commonJWT.AddAuthorizationMetadataToContext(ctxWithCorrelationID, "jwtToken")
		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)

		resendEamilVerificationResponse, err := grpcClient.ResendEmailVerification(
			ctxAuth,
			&pb_authentication.ResendEmailVerificationRequest{},
		)

		assert.Nil(t, resendEamilVerificationResponse)
		assert.Error(t, err)
		assert.Equal(t, "rpc error: code = InvalidArgument desc = invalid_user_id", err.Error())
	})

	t.Run("Verify_Email_Success", func(t *testing.T) {
		ctxWithCorrelationID := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()
		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
		if err != nil {
			t.Fatal(err)
		}

		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)

		_, err = grpcClient.Register(
			ctxWithCorrelationID,
			registerRequest,
		)
		if err != nil {
			t.Fatal(err)
		}

		client, err := mongo.NewClient(options.Client().ApplyURI(envParams.MockMongoServer.URI()))
		if err != nil {
			t.Fatal(err)
		}
		err = client.Connect(ctxWithCorrelationID)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Disconnect(ctxWithCorrelationID)

		userCollection := client.Database("qd_authentication").Collection("user")
		tokenCollection := client.Database("qd_authentication").Collection("token")
		var foundUser model.User
		err = userCollection.FindOne(ctxWithCorrelationID, bson.M{"email": email}).Decode(&foundUser)
		if err != nil {
			t.Fatal(err)
		}
		var foundToken model.Token
		err = tokenCollection.FindOne(ctxWithCorrelationID, bson.M{"userID": foundUser.ID}).Decode(&foundToken)
		if err != nil {
			t.Fatal(err)
		}

		testFirebaseToken := "test-firebase-token"
		envParams.MockFirebaseService.EXPECT().CreateCustomToken(
			gomock.Any(),
			foundUser.ID.Hex(),
		).Return(
			testFirebaseToken,
			nil,
		)

		verifyEmailResponse, err := grpcClient.VerifyEmail(
			ctxWithCorrelationID, &pb_authentication.VerifyEmailRequest{
				VerificationToken: mockEmailService.LastCapturedEmailVerificationToken,
				UserID:            foundToken.UserID.Hex(),
			},
		)

		assert.NotNil(t, verifyEmailResponse)
		assert.NoError(t, err)
		assert.NotNil(t, verifyEmailResponse.AuthToken)
		assert.NotNil(t, verifyEmailResponse.RefreshToken)
		assert.Equal(t, testFirebaseToken, verifyEmailResponse.FirebaseToken, "Firebase token should be included in the response")
	})

	t.Run("Refresh_Token_Error", func(t *testing.T) {
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()
		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
		assert.NoError(t, err)

		if err != nil {
			t.Fatal(err)
		}
		ctxWithCorrelationID := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		ctxAuth := commonJWT.AddAuthorizationMetadataToContext(ctxWithCorrelationID, "wrong-token")

		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)

		refreshTokenResponse, err := grpcClient.RefreshToken(
			ctxAuth,
			&pb_authentication.RefreshTokenRequest{},
		)

		assert.Error(t, err)
		assert.Nil(t, refreshTokenResponse)
		assert.Equal(t, "rpc error: code = Unauthenticated desc = Invalid or expired token", err.Error())
	})

	t.Run("Refresh_Token_Success", func(t *testing.T) {
		ctxWithCorrelationID := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()
		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
		if err != nil {
			t.Fatal(err)
		}

		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)

		_, err = grpcClient.Register(
			ctxWithCorrelationID,
			registerRequest,
		)
		if err != nil {
			t.Fatal(err)
		}

		testFirebaseToken := "test-firebase-token"
		envParams.MockFirebaseService.EXPECT().CreateCustomToken(
			gomock.Any(),
			gomock.Any(),
		).Return(
			testFirebaseToken,
			nil,
		)
		authenticateResponse, err := grpcClient.Authenticate(ctxWithCorrelationID, &pb_authentication.AuthenticateRequest{
			Email:    registerRequest.Email,
			Password: password,
		})
		if err != nil {
			t.Fatal(err)
		}

		ctxAuth := commonJWT.AddAuthorizationMetadataToContext(ctxWithCorrelationID, authenticateResponse.RefreshToken)

		refreshTokenResponse, err := grpcClient.RefreshToken(
			ctxAuth,
			&pb_authentication.RefreshTokenRequest{},
		)
		if err != nil {
			t.Fatal(err)
		}

		authClaims, err := tokenInspector.GetClaimsFromTokenString(authenticateResponse.AuthToken)
		if err != nil {
			t.Fatal(err)
		}
		refreshClaims, err := tokenInspector.GetClaimsFromTokenString(authenticateResponse.RefreshToken)
		if err != nil {
			t.Fatal(err)
		}

		assert.NoError(t, err)
		assert.NotNil(t, refreshTokenResponse)
		assert.NotNil(t, refreshTokenResponse.AuthToken)
		assert.NotNil(t, refreshTokenResponse.RefreshToken)
		assert.Empty(t, refreshTokenResponse.FirebaseToken, "Firebase token should be empty for refresh token response")
		assert.Equal(t, registerRequest.Email, authClaims.Email)
		assert.Equal(t, registerRequest.Email, refreshClaims.Email)
	})

	t.Run("Refresh_Token_Type_Error", func(t *testing.T) {
		ctxWithCorrelationID := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()
		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
		if err != nil {
			t.Fatal(err)
		}

		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)

		_, err = grpcClient.Register(
			ctxWithCorrelationID,
			registerRequest,
		)
		if err != nil {
			t.Fatal(err)
		}

		testFirebaseToken := "test-firebase-token"
		envParams.MockFirebaseService.EXPECT().CreateCustomToken(
			gomock.Any(),
			gomock.Any(),
		).Return(
			testFirebaseToken,
			nil,
		)
		authenticateResponse, err := grpcClient.Authenticate(ctxWithCorrelationID, &pb_authentication.AuthenticateRequest{
			Email:    registerRequest.Email,
			Password: password,
		})
		if err != nil {
			t.Fatal(err)
		}

		ctxAuth := commonJWT.AddAuthorizationMetadataToContext(ctxWithCorrelationID, authenticateResponse.AuthToken)
		refreshTokenResponse, err := grpcClient.RefreshToken(
			ctxAuth,
			&pb_authentication.RefreshTokenRequest{},
		)

		assert.Error(t, err)
		assert.Nil(t, refreshTokenResponse)
		assert.EqualError(t, err, "rpc error: code = Unauthenticated desc = Not a refresh token")
	})

	t.Run("CompleteResetPassword_EmailNotFound_Success", func(t *testing.T) {
		ctxWithCorrelationID := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()
		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
		if err != nil {
			t.Fatal(err)
		}

		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)

		forgotPasswordResponse, err := grpcClient.ForgotPassword(ctxWithCorrelationID, &pb_authentication.ForgotPasswordRequest{
			Email: email,
		})

		assert.NoError(t, err)
		assert.NotNil(t, forgotPasswordResponse)
		assert.Equal(t, "Forgot password request successful", forgotPasswordResponse.Message)
		assert.True(t, forgotPasswordResponse.Success)
	})

	t.Run("CompleteResetPassword_Success", func(t *testing.T) {
		ctxWithCorrelationID := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()
		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
		if err != nil {
			t.Fatal(err)
		}

		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)

		_, err = grpcClient.Register(
			ctxWithCorrelationID,
			registerRequest,
		)
		if err != nil {
			t.Fatal(err)
		}

		testFirebaseToken := "test-firebase-token"
		envParams.MockFirebaseService.EXPECT().CreateCustomToken(
			gomock.Any(),
			gomock.Any(),
		).Return(
			testFirebaseToken,
			nil,
		)
		_, err = grpcClient.Authenticate(ctxWithCorrelationID, &pb_authentication.AuthenticateRequest{
			Email:    registerRequest.Email,
			Password: registerRequest.Password,
		})
		if err != nil {
			t.Fatal(err)
		}

		client, err := mongo.NewClient(options.Client().ApplyURI(envParams.MockMongoServer.URI()))
		if err != nil {
			t.Fatal(err)
		}
		err = client.Connect(ctxWithCorrelationID)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Disconnect(ctxWithCorrelationID)

		userCollection := client.Database("qd_authentication").Collection("user")
		tokenCollection := client.Database("qd_authentication").Collection("token")
		var foundUser model.User
		err = userCollection.FindOne(ctxWithCorrelationID, bson.M{"email": email}).Decode(&foundUser)
		if err != nil {
			t.Fatal(err)
		}
		var foundToken model.Token
		err = tokenCollection.FindOne(ctxWithCorrelationID, bson.M{"userID": foundUser.ID}).Decode(&foundToken)
		if err != nil {
			t.Fatal(err)
		}

		envParams.MockFirebaseService.EXPECT().CreateCustomToken(
			gomock.Any(),
			foundUser.ID.Hex(),
		).Return(
			testFirebaseToken,
			nil,
		)
		_, err = grpcClient.VerifyEmail(
			commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID),
			&pb_authentication.VerifyEmailRequest{
				VerificationToken: mockEmailService.LastCapturedEmailVerificationToken,
				UserID:            foundUser.ID.Hex(),
			},
		)
		if err != nil {
			t.Fatal(err)
		}

		forgotPasswordResponse, err := grpcClient.ForgotPassword(ctxWithCorrelationID, &pb_authentication.ForgotPasswordRequest{
			Email: email,
		})
		assert.NoError(t, err)
		assert.NotNil(t, forgotPasswordResponse)
		assert.Equal(t, "Forgot password request successful", forgotPasswordResponse.Message)
		assert.True(t, forgotPasswordResponse.Success)

		err = tokenCollection.FindOne(ctxWithCorrelationID, bson.M{"userID": foundUser.ID}).Decode(&foundToken)
		if err != nil {
			t.Fatal(err)
		}

		verifyPasswordResetTokenResponse, err := grpcClient.VerifyResetPasswordToken(ctxWithCorrelationID, &pb_authentication.VerifyResetPasswordTokenRequest{
			UserID: foundToken.UserID.Hex(),
			Token:  mockEmailService.LastCapturedPasswordResetToken,
		})

		assert.NoError(t, err)
		assert.NotNil(t, verifyPasswordResetTokenResponse)
		assert.True(t, verifyPasswordResetTokenResponse.IsValid)
		assert.Equal(t, "Verify reset password token successful", verifyPasswordResetTokenResponse.Message)

		newPassword := "NewPassword@000!"
		resetPasswordResponse, err := grpcClient.ResetPassword(ctxWithCorrelationID, &pb_authentication.ResetPasswordRequest{
			UserID:      foundToken.UserID.Hex(),
			Token:       mockEmailService.LastCapturedPasswordResetToken,
			NewPassword: newPassword,
		})

		assert.NoError(t, err)
		assert.NotNil(t, resetPasswordResponse)
		assert.True(t, resetPasswordResponse.Success)
		assert.Equal(t, "Reset password successful", resetPasswordResponse.Message)

		envParams.MockFirebaseService.EXPECT().CreateCustomToken(
			gomock.Any(),
			foundUser.ID.Hex(),
		).Return(
			testFirebaseToken,
			nil,
		)
		authenticateResponse, err := grpcClient.Authenticate(ctxWithCorrelationID, &pb_authentication.AuthenticateRequest{
			Email:    foundUser.Email,
			Password: newPassword,
		})
		if err != nil {
			t.Fatal(err)
		}

		authClaims, err := tokenInspector.GetClaimsFromTokenString(authenticateResponse.AuthToken)
		if err != nil {
			t.Fatal(err)
		}
		refreshClaims, err := tokenInspector.GetClaimsFromTokenString(authenticateResponse.RefreshToken)
		if err != nil {
			t.Fatal(err)
		}

		assert.NoError(t, err)
		assert.NotNil(t, authenticateResponse)
		assert.NotNil(t, authenticateResponse.AuthToken)
		assert.NotNil(t, authenticateResponse.RefreshToken)
		assert.Equal(t, foundUser.Email, authClaims.Email)
		assert.Equal(t, foundUser.Email, refreshClaims.Email)
	})

	t.Run("DeleteAccount_NotVerified_Success", func(t *testing.T) {
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()

		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
		assert.NoError(t, err)

		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)

		// Register user but do NOT verify
		unverifiedEmail := "delete_unverified@test.com"
		unverifiedPassword := "Password123!"
		ctxWithCorrelationID := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		_, err = grpcClient.Register(
			ctxWithCorrelationID,
			&pb_authentication.RegisterRequest{
				Email:       unverifiedEmail,
				Password:    unverifiedPassword,
				FirstName:   "DeleteUnverified",
				LastName:    "User",
				DateOfBirth: timestamppb.New(time.Now().AddDate(-20, 0, 0)),
			},
		)
		assert.NoError(t, err, "Registration for not-verified user failed")

		testFirebaseToken := "test-firebase-token"
		envParams.MockFirebaseService.EXPECT().CreateCustomToken(
			gomock.Any(),
			gomock.Any(),
		).Return(
			testFirebaseToken,
			nil,
		)
		// Authenticate user
		authResp, err := grpcClient.Authenticate(
			ctxWithCorrelationID,
			&pb_authentication.AuthenticateRequest{
				Email:    unverifiedEmail,
				Password: unverifiedPassword,
			},
		)
		assert.NoError(t, err, "Authentication for unverified user must succeed (assuming no block on unverified users)")

		client, err := mongo.NewClient(options.Client().ApplyURI(envParams.MockMongoServer.URI()))
		assert.NoError(t, err)

		err = client.Connect(ctxWithCorrelationID)
		assert.NoError(t, err)
		defer client.Disconnect(ctxWithCorrelationID)

		userCollection := client.Database("qd_authentication").Collection("user")
		tokenCollection := client.Database("qd_authentication").Collection("token")

		// Ensure user and tokens exist
		var unverifiedUser model.User
		err = userCollection.FindOne(ctxWithCorrelationID, bson.M{"email": unverifiedEmail}).Decode(&unverifiedUser)
		assert.NoError(t, err)
		assert.Equal(t, unverifiedUser.Email, unverifiedEmail)
		count, err := tokenCollection.CountDocuments(ctxWithCorrelationID, bson.M{"userID": unverifiedUser.ID})
		assert.NoError(t, err)
		assert.Equal(t, int64(1), count, "There should be one token")

		// Add Auth token to context
		authCtx := commonJWT.AddAuthorizationMetadataToContext(ctxWithCorrelationID, authResp.AuthToken)

		// Call DeleteAccount
		deleteResp, err := grpcClient.DeleteAccount(
			authCtx,
			&pb_authentication.DeleteAccountRequest{},
		)
		assert.NoError(t, err, "Expected successful delete for unverified user")
		assert.NotNil(t, deleteResp)
		assert.True(t, deleteResp.Success)
		assert.Equal(t, "User account deleted successfully", deleteResp.Message)

		// Ensure user no longer exists
		var foundUser model.User
		err = userCollection.FindOne(ctxWithCorrelationID, bson.M{"email": unverifiedEmail}).Decode(&foundUser)
		assert.Error(t, err, "User should be removed from DB")
		assert.EqualError(t, err, "mongo: no documents in result")

		// Ensure no tokens remain for that user
		count, err = tokenCollection.CountDocuments(ctxWithCorrelationID, bson.M{"userID": unverifiedUser.ID})
		assert.NoError(t, err)
		assert.Equal(t, int64(0), count, "All tokens for user should be removed")
	})

	t.Run("DeleteAccount_Verified_Success", func(t *testing.T) {
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()

		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
		assert.NoError(t, err)

		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)

		// 1) Register user
		verifiedEmail := "delete_verified@test.com"
		verifiedPassword := "Password123!"
		ctxWithCorrelationID := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		_, err = grpcClient.Register(
			ctxWithCorrelationID,
			&pb_authentication.RegisterRequest{
				Email:       verifiedEmail,
				Password:    verifiedPassword,
				FirstName:   "DeleteVerified",
				LastName:    "User",
				DateOfBirth: timestamppb.New(time.Now().AddDate(-20, 0, 0)),
			},
		)
		assert.NoError(t, err)

		// Retrieve user + token from DB, then verify email
		client, err := mongo.NewClient(options.Client().ApplyURI(envParams.MockMongoServer.URI()))
		assert.NoError(t, err)

		err = client.Connect(ctxWithCorrelationID)
		assert.NoError(t, err)
		defer client.Disconnect(ctxWithCorrelationID)

		userCollection := client.Database("qd_authentication").Collection("user")
		tokenCollection := client.Database("qd_authentication").Collection("token")

		var foundUser model.User
		err = userCollection.FindOne(ctxWithCorrelationID, bson.M{"email": verifiedEmail}).Decode(&foundUser)
		assert.NoError(t, err)

		var foundToken model.Token
		err = tokenCollection.FindOne(ctxWithCorrelationID, bson.M{"userID": foundUser.ID}).Decode(&foundToken)
		assert.NoError(t, err)

		testFirebaseToken := "test-firebase-token"
		envParams.MockFirebaseService.EXPECT().CreateCustomToken(
			gomock.Any(),
			foundUser.ID.Hex(),
		).Return(
			testFirebaseToken,
			nil,
		)
		// Simulate reading the verification token from the captured email
		verifyResp, err := grpcClient.VerifyEmail(
			ctxWithCorrelationID,
			&pb_authentication.VerifyEmailRequest{
				UserID:            foundToken.UserID.Hex(),
				VerificationToken: mockEmailService.LastCapturedEmailVerificationToken,
			},
		)
		assert.NoError(t, err, "Failed to verify user")
		assert.NotNil(t, verifyResp.AuthToken)
		assert.NotNil(t, verifyResp.RefreshToken)

		// Re-fetch user to confirm verified
		err = userCollection.FindOne(ctxWithCorrelationID, bson.M{"email": verifiedEmail}).Decode(&foundUser)
		assert.NoError(t, err)
		assert.Equal(t, model.AccountStatusVerified, foundUser.AccountStatus)

		testFirebaseToken = "test-firebase-token"
		envParams.MockFirebaseService.EXPECT().CreateCustomToken(
			gomock.Any(),
			foundUser.ID.Hex(),
		).Return(
			testFirebaseToken,
			nil,
		)
		// Authenticate user
		authResp, err := grpcClient.Authenticate(
			ctxWithCorrelationID,
			&pb_authentication.AuthenticateRequest{
				Email:    verifiedEmail,
				Password: verifiedPassword,
			},
		)
		assert.NoError(t, err)

		// Call DeleteAccount
		authCtx := commonJWT.AddAuthorizationMetadataToContext(ctxWithCorrelationID, authResp.AuthToken)
		deleteResp, err := grpcClient.DeleteAccount(
			authCtx,
			&pb_authentication.DeleteAccountRequest{},
		)
		assert.NoError(t, err)
		assert.NotNil(t, deleteResp)
		assert.True(t, deleteResp.Success)
		assert.Equal(t, "User account deleted successfully", deleteResp.Message)

		// Confirm user + tokens removed from DB
		err = userCollection.FindOne(ctxWithCorrelationID, bson.M{"email": verifiedEmail}).Decode(&foundUser)
		assert.Error(t, err, "Verified user should be removed from DB after DeleteAccount")
		assert.EqualError(t, err, "mongo: no documents in result")

		count, err := tokenCollection.CountDocuments(ctxWithCorrelationID, bson.M{"email": verifiedEmail})
		assert.NoError(t, err)
		assert.Equal(t, int64(0), count, "All tokens for user should be removed after DeleteAccount")
	})

	t.Run("HasPaidFeatures_Claim_Behavior", func(t *testing.T) {
		envParams := setUpTestEnvironment(t)
		defer envParams.Application.Close()
		defer envParams.MockMongoServer.Stop()
		connection, err := commonTLS.CreateGRPCConnection(
			envParams.Application.GetGRPCServerAddress(),
			envParams.MockConfig.TLSEnabled,
		)
		assert.NoError(t, err)

		ctxWithCorrelationID := commonLogger.AddCorrelationIDToOutgoingContext(context.Background(), correlationID)
		grpcClient := pb_authentication.NewAuthenticationServiceClient(connection)

		// Register and authenticate user
		_, err = grpcClient.Register(
			ctxWithCorrelationID,
			registerRequest,
		)
		assert.NoError(t, err)

		testFirebaseToken := "test-firebase-token"
		envParams.MockFirebaseService.EXPECT().CreateCustomToken(
			gomock.Any(),
			gomock.Any(),
		).Return(
			testFirebaseToken,
			nil,
		)

		// First authentication - HasPaidFeatures should be false
		authResponse, err := grpcClient.Authenticate(ctxWithCorrelationID, &pb_authentication.AuthenticateRequest{
			Email:    registerRequest.Email,
			Password: password,
		})
		assert.NoError(t, err)
		assert.NotNil(t, authResponse)

		// Verify HasPaidFeatures is false in auth token
		authClaims, err := tokenInspector.GetClaimsFromTokenString(authResponse.AuthToken)
		assert.NoError(t, err)
		assert.False(t, authClaims.HasPaidFeatures, "HasPaidFeatures should be false in initial auth token")

		// Refresh token and verify HasPaidFeatures is still false
		ctxWithRefreshToken := commonJWT.AddAuthorizationMetadataToContext(ctxWithCorrelationID, authResponse.RefreshToken)
		refreshResponse, err := grpcClient.RefreshToken(
			ctxWithRefreshToken,
			&pb_authentication.RefreshTokenRequest{},
		)
		assert.NoError(t, err)
		assert.NotNil(t, refreshResponse)

		// Verify HasPaidFeatures is false in refreshed token
		refreshedAuthClaims, err := tokenInspector.GetClaimsFromTokenString(refreshResponse.AuthToken)
		assert.NoError(t, err)
		assert.False(t, refreshedAuthClaims.HasPaidFeatures, "HasPaidFeatures should be false in refreshed token")

		// Update user's HasPaidFeatures to true in MongoDB
		client, err := mongo.NewClient(options.Client().ApplyURI(envParams.MockMongoServer.URI()))
		assert.NoError(t, err)
		err = client.Connect(ctxWithCorrelationID)
		assert.NoError(t, err)
		defer client.Disconnect(ctxWithCorrelationID)

		collection := client.Database("qd_authentication").Collection("user")
		_, err = collection.UpdateOne(
			ctxWithCorrelationID,
			bson.M{"email": registerRequest.Email},
			bson.M{"$set": bson.M{"hasPaidFeatures": true}},
		)
		assert.NoError(t, err)

		// Authenticate again - HasPaidFeatures should now be true
		envParams.MockFirebaseService.EXPECT().CreateCustomToken(
			gomock.Any(),
			gomock.Any(),
		).Return(
			testFirebaseToken,
			nil,
		)

		updatedAuthResponse, err := grpcClient.Authenticate(ctxWithCorrelationID, &pb_authentication.AuthenticateRequest{
			Email:    registerRequest.Email,
			Password: password,
		})
		assert.NoError(t, err)
		assert.NotNil(t, updatedAuthResponse)

		// Verify HasPaidFeatures is true in new auth token
		updatedAuthClaims, err := tokenInspector.GetClaimsFromTokenString(updatedAuthResponse.AuthToken)
		assert.NoError(t, err)
		assert.True(t, updatedAuthClaims.HasPaidFeatures, "HasPaidFeatures should be true in updated auth token")

		// Refresh token again and verify HasPaidFeatures is still true
		ctxWithUpdatedRefreshToken := commonJWT.AddAuthorizationMetadataToContext(ctxWithCorrelationID, updatedAuthResponse.RefreshToken)
		updatedRefreshResponse, err := grpcClient.RefreshToken(
			ctxWithUpdatedRefreshToken,
			&pb_authentication.RefreshTokenRequest{},
		)
		assert.NoError(t, err)
		assert.NotNil(t, updatedRefreshResponse)

		// Verify HasPaidFeatures is true in refreshed token
		updatedRefreshedAuthClaims, err := tokenInspector.GetClaimsFromTokenString(updatedRefreshResponse.AuthToken)
		assert.NoError(t, err)
		assert.True(t, updatedRefreshedAuthClaims.HasPaidFeatures, "HasPaidFeatures should be true in updated refreshed token")
	})
}

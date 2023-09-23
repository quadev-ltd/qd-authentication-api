package server_grpc_test

import (
	"context"
	"errors"
	grpcServerService "qd_authentication_api/internal/grpc_server"
	"qd_authentication_api/internal/model"
	validationErrorsMock "qd_authentication_api/internal/model/mock"
	"qd_authentication_api/internal/service/mock"
	"qd_authentication_api/pb/gen/go/pb_authentication"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAuthenticationServiceServer(test *testing.T) {
	// Create a sample registerRequest for testing.
	registerRequest := &pb_authentication.RegisterRequest{
		Email:       "test@example.com",
		Password:    "password",
		FirstName:   "John",
		LastName:    "Doe",
		DateOfBirth: timestamppb.New(time.Now()),
	}

	// Create a sample request for testing.
	verifyEmailRequest := &pb_authentication.VerifyEmailRequest{
		VerificationToken: "some_verification_token",
	}

	authenticateRequest := &pb_authentication.AuthenticateRequest{
		Email:    "test@example.com",
		Password: "password",
	}

	test.Run("Registration error wrong email or password", func(test *testing.T) {

		// Create a new instance of the controller for managing mocks.
		controller := gomock.NewController(test)
		defer controller.Finish()

		// Create a mock for your AuthenticationService.
		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)

		// Create an instance of your gRPC server with the mock service.
		server := grpcServerService.AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		mockValidationError := validator.ValidationErrors{
			&validationErrorsMock.CustomValidationError{
				FieldName: "FieldName",
			},
		}

		// Set up expectations on your mock service.
		authenticationServiceMock.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(mockValidationError)

		// Call the Register function on your gRPC server.
		response, returnedError := server.Register(context.Background(), registerRequest)

		// Assert that the error returned by the server matches the expected error.
		assert.Equal(test, "rpc error: code = InvalidArgument desc = Registration failed: FieldName", returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("Registration internal server error", func(test *testing.T) {

		// Create a new instance of the controller for managing mocks.
		controller := gomock.NewController(test)
		defer controller.Finish()

		// Create a mock for your AuthenticationService.
		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)

		// Create an instance of your gRPC server with the mock service.
		server := grpcServerService.AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		// Define the error you want the Register function to return.
		mockValidationError := errors.New("some error")

		// Set up expectations on your mock service.
		authenticationServiceMock.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(mockValidationError)

		// Call the Register function on your gRPC server.
		response, returnedError := server.Register(context.Background(), registerRequest)

		// Assert that the error returned by the server matches the expected error.
		assert.Equal(test, "rpc error: code = Internal desc = Registration failed: internal server error", returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("Registration error email in use", func(test *testing.T) {

		// Create a new instance of the controller for managing mocks.
		controller := gomock.NewController(test)
		defer controller.Finish()

		// Create a mock for your AuthenticationService.
		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)

		// Create an instance of your gRPC server with the mock service.
		server := grpcServerService.AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		// Define the error you want the Register function to return.
		mockEmailInUseError := &model.EmailInUseError{Email: "test@example.com"}

		// Set up expectations on your mock service.
		authenticationServiceMock.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(mockEmailInUseError)

		// Call the Register function on your gRPC server.
		response, returnedError := server.Register(context.Background(), registerRequest)

		// Assert that the error returned by the server matches the expected error.
		assert.Equal(
			test,
			"rpc error: code = InvalidArgument desc = Registration failed: email already in use",
			returnedError.Error(),
		)
		assert.Nil(test, response)
	})

	test.Run("Registration success", func(test *testing.T) {

		// Create a new instance of the controller for managing mocks.
		controller := gomock.NewController(test)
		defer controller.Finish()

		// Create a mock for your AuthenticationService.
		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)

		// Create an instance of your gRPC server with the mock service.
		server := grpcServerService.AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}
		successfulResponse := &pb_authentication.RegisterResponse{
			Success: true,
			Message: "Registration successful",
		}
		// Set up expectations on your mock service.
		authenticationServiceMock.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil)

		// Call the Register function on your gRPC server.
		response, returnedError := server.Register(context.Background(), registerRequest)

		assert.Nil(
			test,
			returnedError,
		)
		assert.Equal(test, response.Message, successfulResponse.Message)
		assert.Equal(test, response.Success, successfulResponse.Success)
	})

	test.Run("Email verification error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)

		server := grpcServerService.AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		mockVerifyEmailError := errors.New("some verification error")

		authenticationServiceMock.EXPECT().
			Verify(gomock.Any()).
			Return(mockVerifyEmailError)

		response, returnedError := server.VerifyEmail(context.Background(), verifyEmailRequest)

		assert.Equal(test, status.Error(codes.InvalidArgument, mockVerifyEmailError.Error()), returnedError)
		assert.Nil(test, response)
	})

	test.Run("Verify Email success", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)

		server := grpcServerService.AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		successfulResponse := &pb_authentication.VerifyEmailResponse{
			Success: true,
			Message: "Email verified successfully",
		}

		authenticationServiceMock.EXPECT().
			Verify(gomock.Any()).
			Return(nil)

		// Call the VerifyEmail function on your gRPC server.
		response, returnedError := server.VerifyEmail(context.Background(), verifyEmailRequest)

		// Assert that there is no error returned, and the response matches the expected response.
		assert.Nil(test, returnedError)
		assert.Equal(test, successfulResponse, response)
	})

	test.Run("Authenticate returns Invalid email or password error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)

		server := grpcServerService.AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		invalidEmailOrPasswordError := &model.WrongEmailOrPassword{
			FieldName: "Email",
		}
		expectedError := status.Errorf(codes.Unauthenticated, "Invalid email or password")

		authenticationServiceMock.EXPECT().
			Authenticate(gomock.Any(), gomock.Any()).
			Return(nil, invalidEmailOrPasswordError)

		response, returnedError := server.Authenticate(context.Background(), authenticateRequest)

		assert.Equal(test, expectedError.Error(), returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("Authenticate internal server error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)

		server := grpcServerService.AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		authenticationError := errors.New("some error")
		expectedError := status.Errorf(codes.Internal, "Internal server error")

		authenticationServiceMock.EXPECT().
			Authenticate(gomock.Any(), gomock.Any()).
			Return(nil, authenticationError)

		response, returnedError := server.Authenticate(context.Background(), authenticateRequest)

		assert.Equal(test, expectedError.Error(), returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("Authenticate success", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)

		server := grpcServerService.AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		authenticateResponse := &model.AuthTokensResponse{
			AuthToken:          "some_auth_token",
			AuthTokenExpiry:    time.Now(),
			RefreshToken:       "some_refresh_token",
			RefreshTokenExpiry: time.Now(),
			UserEmail:          "test@example.com",
		}

		successfulResponse := &pb_authentication.AuthenticateResponse{
			AuthToken:          authenticateResponse.AuthToken,
			AuthTokenExpiry:    timestamppb.New(authenticateResponse.AuthTokenExpiry),
			RefreshToken:       authenticateResponse.RefreshToken,
			RefreshTokenExpiry: timestamppb.New(authenticateResponse.RefreshTokenExpiry),
			UserEmail:          authenticateResponse.UserEmail,
		}

		authenticationServiceMock.EXPECT().
			Authenticate(gomock.Any(), gomock.Any()).
			Return(authenticateResponse, nil)

		response, returnedError := server.Authenticate(context.Background(), authenticateRequest)

		assert.Nil(test, returnedError)
		assert.Equal(test, successfulResponse, response)
	})
}

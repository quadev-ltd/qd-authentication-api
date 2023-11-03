package grpc_server

import (
	"context"
	"errors"
	loggerMock "qd_authentication_api/internal/log/mock"
	"qd_authentication_api/internal/model"
	validationErrorsMock "qd_authentication_api/internal/model/mock"
	"qd_authentication_api/internal/service"
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
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)
		loggerMock := loggerMock.NewMockLoggerer(controller)
		ctx := context.WithValue(context.Background(), LoggerKey, loggerMock)

		server := AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		mockValidationError := validator.ValidationErrors{
			&validationErrorsMock.CustomValidationError{
				FieldName: "FieldName",
			},
		}

		authenticationServiceMock.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(mockValidationError)

		response, returnedError := server.Register(ctx, registerRequest)

		assert.Equal(test, "rpc error: code = InvalidArgument desc = Registration failed: FieldName", returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("Registration internal server error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)
		loggerMock := loggerMock.NewMockLoggerer(controller)
		ctx := context.WithValue(context.Background(), LoggerKey, loggerMock)

		server := AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		mockValidationError := errors.New("some error")

		authenticationServiceMock.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(mockValidationError)
		loggerMock.EXPECT().Error(mockValidationError, "Registration failed")

		response, returnedError := server.Register(ctx, registerRequest)

		assert.Equal(test, "rpc error: code = Internal desc = Registration failed: internal server error", returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("Registration error email in use", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)
		loggerMock := loggerMock.NewMockLoggerer(controller)
		ctx := context.WithValue(context.Background(), LoggerKey, loggerMock)

		server := AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		mockEmailInUseError := &model.EmailInUseError{Email: "test@example.com"}

		authenticationServiceMock.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(mockEmailInUseError)

		response, returnedError := server.Register(ctx, registerRequest)

		assert.Equal(
			test,
			"rpc error: code = InvalidArgument desc = Registration failed: email already in use",
			returnedError.Error(),
		)
		assert.Nil(test, response)
	})

	test.Run("Registration success", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)
		loggerMock := loggerMock.NewMockLoggerer(controller)
		ctx := context.WithValue(context.Background(), LoggerKey, loggerMock)

		server := AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}
		successfulResponse := &pb_authentication.RegisterResponse{
			Success: true,
			Message: "Registration successful.",
		}

		authenticationServiceMock.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil)
		loggerMock.EXPECT().Info("Registration successful.")

		response, returnedError := server.Register(ctx, registerRequest)

		assert.Nil(
			test,
			returnedError,
		)
		assert.Equal(test, response.Message, successfulResponse.Message)
		assert.Equal(test, response.Success, successfulResponse.Success)
	})

	test.Run("Email verification internal server error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)
		loggerMock := loggerMock.NewMockLoggerer(controller)
		ctx := context.WithValue(context.Background(), LoggerKey, loggerMock)

		server := AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		mockVerifyEmailError := errors.New("some verification error")

		authenticationServiceMock.EXPECT().
			VerifyEmail(gomock.Any()).
			Return(mockVerifyEmailError)
		loggerMock.EXPECT().Error(mockVerifyEmailError, "Email verification failed")

		response, returnedError := server.VerifyEmail(ctx, verifyEmailRequest)

		assert.Equal(test, status.Error(codes.Internal, "Internal server error"), returnedError)
		assert.Nil(test, response)
	})

	test.Run("Email verification service error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)
		loggerMock := loggerMock.NewMockLoggerer(controller)
		ctx := context.WithValue(context.Background(), LoggerKey, loggerMock)

		server := AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		mockVerifyEmailError := &service.ServiceError{Message: "some error"}

		authenticationServiceMock.EXPECT().
			VerifyEmail(gomock.Any()).
			Return(mockVerifyEmailError)
		loggerMock.EXPECT().Error(mockVerifyEmailError, "Email verification failed")

		response, returnedError := server.VerifyEmail(ctx, verifyEmailRequest)

		assert.Equal(test, status.Error(codes.InvalidArgument, mockVerifyEmailError.Error()), returnedError)
		assert.Nil(test, response)
	})

	test.Run("Verify Email success", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)
		loggerMock := loggerMock.NewMockLoggerer(controller)
		ctx := context.WithValue(context.Background(), LoggerKey, loggerMock)

		server := AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		successfulResponse := &pb_authentication.VerifyEmailResponse{
			Success: true,
			Message: "Email verified successfully.",
		}

		authenticationServiceMock.EXPECT().
			VerifyEmail(gomock.Any()).
			Return(nil)
		loggerMock.EXPECT().Info("Email verified successfully.")

		response, returnedError := server.VerifyEmail(ctx, verifyEmailRequest)

		assert.Nil(test, returnedError)
		assert.Equal(test, successfulResponse, response)
	})

	test.Run("Authenticate returns Invalid email or password error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)
		loggerMock := loggerMock.NewMockLoggerer(controller)
		ctx := context.WithValue(context.Background(), LoggerKey, loggerMock)

		server := AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		invalidEmailOrPasswordError := &model.WrongEmailOrPassword{
			FieldName: "Email",
		}
		expectedError := status.Errorf(codes.Unauthenticated, "Invalid email or password.")

		authenticationServiceMock.EXPECT().
			Authenticate(gomock.Any(), gomock.Any()).
			Return(nil, invalidEmailOrPasswordError)
		loggerMock.EXPECT().Error(invalidEmailOrPasswordError, "Invalid email or password.")

		response, returnedError := server.Authenticate(ctx, authenticateRequest)

		assert.Equal(test, expectedError.Error(), returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("Authenticate internal server error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)
		loggerMock := loggerMock.NewMockLoggerer(controller)
		ctx := context.WithValue(context.Background(), LoggerKey, loggerMock)

		server := AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		authenticationError := errors.New("some error")
		expectedError := status.Errorf(codes.Internal, "Internal server error.")

		authenticationServiceMock.EXPECT().
			Authenticate(gomock.Any(), gomock.Any()).
			Return(nil, authenticationError)
		loggerMock.EXPECT().Error(authenticationError, "Internal error.")

		response, returnedError := server.Authenticate(ctx, authenticateRequest)

		assert.Equal(test, expectedError.Error(), returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("Authenticate success", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)
		loggerMock := loggerMock.NewMockLoggerer(controller)
		ctx := context.WithValue(context.Background(), LoggerKey, loggerMock)

		server := AuthenticationServiceServer{
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
		loggerMock.EXPECT().Info("Authentication successful.")

		response, returnedError := server.Authenticate(ctx, authenticateRequest)

		assert.Nil(test, returnedError)
		assert.Equal(test, successfulResponse, response)
	})

	test.Run("ResendEmailVerification_VerifyTokenAndDecodeEmail_Error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)
		loggerMock := loggerMock.NewMockLoggerer(controller)
		ctx := context.WithValue(context.Background(), LoggerKey, loggerMock)

		server := AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		expectedError := errors.New("test error")

		authenticationServiceMock.EXPECT().
			VerifyTokenAndDecodeEmail(gomock.Any()).
			Return(nil, expectedError)
		loggerMock.EXPECT().Error(expectedError, "Failed to verify JWT token")

		response, returnedError := server.ResendEmailVerification(ctx, &pb_authentication.ResendEmailVerificationRequest{})

		assert.Nil(test, response)
		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Unauthenticated desc = Invalid JWT token", returnedError.Error())
	})

	test.Run("ResendEmailVerification_ServiceError_Error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)
		loggerMock := loggerMock.NewMockLoggerer(controller)
		ctx := context.WithValue(context.Background(), LoggerKey, loggerMock)

		server := AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		expectedError := &service.ServiceError{Message: "test error"}

		authenticationServiceMock.EXPECT().
			VerifyTokenAndDecodeEmail(gomock.Any()).
			Return(nil, expectedError)

		response, returnedError := server.ResendEmailVerification(ctx, &pb_authentication.ResendEmailVerificationRequest{})

		assert.Nil(test, response)
		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = InvalidArgument desc = test error", returnedError.Error())
	})

	test.Run("ResendEmailVerification_InvalidArgument_Error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)
		loggerMock := loggerMock.NewMockLoggerer(controller)
		ctx := context.WithValue(context.Background(), LoggerKey, loggerMock)

		server := AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		expectedError := &service.ServiceError{Message: "test error"}
		testEmail := "example@email.com"
		authenticationServiceMock.EXPECT().
			VerifyTokenAndDecodeEmail(gomock.Any()).
			Return(&testEmail, nil)
		authenticationServiceMock.EXPECT().
			ResendEmailVerification(testEmail).
			Return(expectedError)

		response, returnedError := server.ResendEmailVerification(ctx, &pb_authentication.ResendEmailVerificationRequest{})

		assert.Nil(test, response)
		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = InvalidArgument desc = test error", returnedError.Error())
	})

	test.Run("ResendEmailVerification_InternalServerError", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)
		loggerMock := loggerMock.NewMockLoggerer(controller)
		ctx := context.WithValue(context.Background(), LoggerKey, loggerMock)

		server := AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		expectedError := errors.New("test error")
		testEmail := "example@email.com"
		authenticationServiceMock.EXPECT().
			VerifyTokenAndDecodeEmail(gomock.Any()).
			Return(&testEmail, nil)
		authenticationServiceMock.EXPECT().
			ResendEmailVerification(testEmail).
			Return(expectedError)
		loggerMock.EXPECT().Error(expectedError, "Failed to resend email verification")

		response, returnedError := server.ResendEmailVerification(ctx, &pb_authentication.ResendEmailVerificationRequest{})

		assert.Nil(test, response)
		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = Internal server error", returnedError.Error())
	})

	test.Run("ResendEmailVerification_Success", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)
		loggerMock := loggerMock.NewMockLoggerer(controller)
		ctx := context.WithValue(context.Background(), LoggerKey, loggerMock)

		server := AuthenticationServiceServer{
			AuthenticationService: authenticationServiceMock,
		}

		testEmail := "example@email.com"
		authenticationServiceMock.EXPECT().
			VerifyTokenAndDecodeEmail(gomock.Any()).
			Return(&testEmail, nil)
		authenticationServiceMock.EXPECT().
			ResendEmailVerification(testEmail).
			Return(nil)
		loggerMock.EXPECT().Info("Email verification sent successfully")

		response, returnedError := server.ResendEmailVerification(ctx, &pb_authentication.ResendEmailVerificationRequest{})

		assert.Nil(test, returnedError)
		assert.Equal(test, true, response.Success)
		assert.Equal(test, "Email verification sent successfully", response.Message)
	})

}

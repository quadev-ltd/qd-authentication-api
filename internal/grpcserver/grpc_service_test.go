package grpcserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang/mock/gomock"
	"github.com/quadev-ltd/qd-common/pkg/log"
	loggerMock "github.com/quadev-ltd/qd-common/pkg/log/mock"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/service"
	"qd-authentication-api/internal/service/mock"
	"qd-authentication-api/pb/gen/go/pb_authentication"
)

// TODO: use test suite table driven tests

func initialiseTest(test *testing.T) (
	*gomock.Controller,
	*mock.MockAuthenticationServicer,
	*mock.MockTokenServicer,
	*loggerMock.MockLoggerer,
	context.Context,
	AuthenticationServiceServer,
) {
	controller := gomock.NewController(test)

	authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)
	tokenServiceMock := mock.NewMockTokenServicer(controller)
	loggerMock := loggerMock.NewMockLoggerer(controller)
	ctx := context.WithValue(context.Background(), log.LoggerKey, loggerMock)

	server := AuthenticationServiceServer{
		authenticationService: authenticationServiceMock,
		tokenService:          tokenServiceMock,
	}

	return controller, authenticationServiceMock, tokenServiceMock, loggerMock, ctx, server
}

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
	test.Run("Registration_Error_Validation", func(test *testing.T) {
		controller, authenticationServiceMock, _, _, ctx, server := initialiseTest(test)
		defer controller.Finish()

		mockValidationError := validator.ValidationErrors{
			&mock.CustomValidationError{
				FieldName: "FieldName",
			},
		}

		authenticationServiceMock.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(mockValidationError)

		response, returnedError := server.Register(ctx, registerRequest)

		assert.Equal(test, "rpc error: code = InvalidArgument desc = Registration failed: FieldName", returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("Registration_Internal_Server_Error", func(test *testing.T) {
		controller, authenticationServiceMock, _, loggerMock, ctx, server := initialiseTest(test)
		defer controller.Finish()

		mockValidationError := errors.New("some error")

		authenticationServiceMock.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(mockValidationError)
		loggerMock.EXPECT().Error(mockValidationError, "Registration failed")

		response, returnedError := server.Register(ctx, registerRequest)

		assert.Equal(test, "rpc error: code = Internal desc = Registration failed: internal server error", returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("Registration_Error_Email_In_Use", func(test *testing.T) {
		controller, authenticationServiceMock, _, _, ctx, server := initialiseTest(test)
		defer controller.Finish()

		mockEmailInUseError := &model.EmailInUseError{Email: "test@example.com"}

		authenticationServiceMock.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(mockEmailInUseError)

		response, returnedError := server.Register(ctx, registerRequest)

		assert.Equal(
			test,
			"rpc error: code = InvalidArgument desc = Registration failed: email already in use",
			returnedError.Error(),
		)
		assert.Nil(test, response)
	})

	test.Run("Registration_Error_Date_Of_Birth_Not_Provided", func(test *testing.T) {
		registerRequestNoDOB := &pb_authentication.RegisterRequest{
			Email:     "test@example.com",
			Password:  "password",
			FirstName: "John",
			LastName:  "Doe",
		}

		controller, _, _, _, ctx, server := initialiseTest(test)
		defer controller.Finish()

		response, returnedError := server.Register(ctx, registerRequestNoDOB)

		assert.Equal(
			test,
			"rpc error: code = InvalidArgument desc = Date of birth was not provided",
			returnedError.Error(),
		)
		assert.Nil(test, response)
	})

	test.Run("Registration_Error_Email_Not_Sent", func(test *testing.T) {
		controller, authenticationServiceMock, _, loggerMock, ctx, server := initialiseTest(test)
		defer controller.Finish()

		mockServiceError := &service.SendEmailError{Message: "some error"}

		authenticationServiceMock.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(mockServiceError)
		loggerMock.EXPECT().Info("Registration successful")

		response, returnedError := server.Register(ctx, registerRequest)

		assert.NoError(
			test,
			returnedError,
		)
		assert.Equal(test, response.Message, "Registration successful. However, verification email failed to send")
		assert.True(test, response.Success)
	})

	test.Run("Registration_Success", func(test *testing.T) {
		controller, authenticationServiceMock, _, loggerMock, ctx, server := initialiseTest(test)
		defer controller.Finish()
		successfulResponse := &pb_authentication.BaseResponse{
			Success: true,
			Message: "Registration successful",
		}

		authenticationServiceMock.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil)
		loggerMock.EXPECT().Info("Registration successful")

		response, returnedError := server.Register(ctx, registerRequest)

		assert.Nil(
			test,
			returnedError,
		)
		assert.Equal(test, response.Message, successfulResponse.Message)
		assert.Equal(test, response.Success, successfulResponse.Success)
	})

	test.Run("Email verification internal server error", func(test *testing.T) {
		controller, authenticationServiceMock, _, loggerMock, ctx, server := initialiseTest(test)
		defer controller.Finish()

		mockVerifyEmailError := errors.New("some verification error")

		authenticationServiceMock.EXPECT().
			VerifyEmail(gomock.Any(), gomock.Any()).
			Return(mockVerifyEmailError)
		loggerMock.EXPECT().Error(mockVerifyEmailError, "Email verification failed")

		response, returnedError := server.VerifyEmail(ctx, verifyEmailRequest)

		assert.Equal(test, status.Error(codes.Internal, "Internal server error"), returnedError)
		assert.Nil(test, response)
	})

	test.Run("Email verification service error", func(test *testing.T) {
		controller, authenticationServiceMock, _, loggerMock, ctx, server := initialiseTest(test)
		defer controller.Finish()

		mockVerifyEmailError := &service.Error{Message: "some error"}

		authenticationServiceMock.EXPECT().
			VerifyEmail(gomock.Any(), gomock.Any()).
			Return(mockVerifyEmailError)
		loggerMock.EXPECT().Error(mockVerifyEmailError, "Email verification failed")

		response, returnedError := server.VerifyEmail(ctx, verifyEmailRequest)

		assert.Equal(test, status.Error(codes.InvalidArgument, mockVerifyEmailError.Error()), returnedError)
		assert.Nil(test, response)
	})

	test.Run("Verify Email success", func(test *testing.T) {
		controller, authenticationServiceMock, _, loggerMock, ctx, server := initialiseTest(test)
		defer controller.Finish()

		successfulResponse := &pb_authentication.BaseResponse{
			Success: true,
			Message: "Email verified successfully",
		}

		authenticationServiceMock.EXPECT().
			VerifyEmail(gomock.Any(), gomock.Any()).
			Return(nil)
		loggerMock.EXPECT().Info("Email verified successfully")

		response, returnedError := server.VerifyEmail(ctx, verifyEmailRequest)

		assert.Nil(test, returnedError)
		assert.Equal(test, successfulResponse, response)
	})

	test.Run("Authenticate returns Invalid email or password error", func(test *testing.T) {
		controller, authenticationServiceMock, _, loggerMock, ctx, server := initialiseTest(test)
		defer controller.Finish()

		invalidEmailOrPasswordError := &model.WrongEmailOrPassword{
			FieldName: "Email",
		}
		expectedError := status.Errorf(codes.Unauthenticated, "Invalid email or password")

		authenticationServiceMock.EXPECT().
			Authenticate(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, invalidEmailOrPasswordError)
		loggerMock.EXPECT().Error(invalidEmailOrPasswordError, "Invalid email or password")

		response, returnedError := server.Authenticate(ctx, authenticateRequest)

		assert.Equal(test, expectedError.Error(), returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("Authenticate internal server error", func(test *testing.T) {
		controller, authenticationServiceMock, _, loggerMock, ctx, server := initialiseTest(test)
		defer controller.Finish()

		authenticationError := errors.New("some error")
		expectedError := status.Errorf(codes.Internal, "Internal server error")

		authenticationServiceMock.EXPECT().
			Authenticate(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, authenticationError)
		loggerMock.EXPECT().Error(authenticationError, "Internal error")

		response, returnedError := server.Authenticate(ctx, authenticateRequest)

		assert.Equal(test, expectedError.Error(), returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("Authenticate success", func(test *testing.T) {
		controller, authenticationServiceMock, _, loggerMock, ctx, server := initialiseTest(test)
		defer controller.Finish()

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
			Authenticate(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(authenticateResponse, nil)
		loggerMock.EXPECT().Info("Authentication successful")

		response, returnedError := server.Authenticate(ctx, authenticateRequest)

		assert.Nil(test, returnedError)
		assert.Equal(test, successfulResponse, response)
	})

	test.Run("ResendEmailVerification_VerifyJWTToken_Error", func(test *testing.T) {
		controller, _, tokenServiceMock, loggerMock, ctx, server := initialiseTest(test)
		defer controller.Finish()

		expectedError := errors.New("test-error")

		tokenServiceMock.EXPECT().
			VerifyJWTToken(gomock.Any(), gomock.Any()).
			Return(nil, expectedError)
		loggerMock.EXPECT().Error(expectedError, "Failed to verify JWT token")

		response, returnedError := server.ResendEmailVerification(ctx, &pb_authentication.ResendEmailVerificationRequest{
			AuthToken: "test-token",
		})

		assert.Nil(test, response)
		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Unauthenticated desc = Invalid JWT token", returnedError.Error())
	})

	test.Run("ResendEmailVerification_ServiceError_Error", func(test *testing.T) {
		controller, _, tokenServiceMock, _, ctx, server := initialiseTest(test)
		defer controller.Finish()

		expectedError := &service.Error{Message: "test-error"}

		tokenServiceMock.EXPECT().
			VerifyJWTToken(gomock.Any(), gomock.Any()).
			Return(nil, expectedError)

		response, returnedError := server.ResendEmailVerification(ctx, &pb_authentication.ResendEmailVerificationRequest{})

		assert.Nil(test, response)
		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = InvalidArgument desc = test-error", returnedError.Error())
	})

	test.Run("ResendEmailVerification_InvalidArgument_Error", func(test *testing.T) {
		controller, authenticationServiceMock, tokenServiceMock, _, ctx, server := initialiseTest(test)
		defer controller.Finish()

		expectedError := &service.Error{Message: "test error"}
		testEmail := "example@email.com"
		tokenServiceMock.EXPECT().
			VerifyJWTToken(gomock.Any(), gomock.Any()).
			Return(&testEmail, nil)
		authenticationServiceMock.EXPECT().
			ResendEmailVerification(gomock.Any(), testEmail).
			Return(expectedError)

		response, returnedError := server.ResendEmailVerification(ctx, &pb_authentication.ResendEmailVerificationRequest{})

		assert.Nil(test, response)
		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = InvalidArgument desc = test error", returnedError.Error())
	})

	test.Run("ResendEmailVerification_InternalServerError", func(test *testing.T) {
		controller, authenticationServiceMock, tokenServiceMock, loggerMock, ctx, server := initialiseTest(test)
		defer controller.Finish()

		expectedError := errors.New("test error")
		testEmail := "example@email.com"
		tokenServiceMock.EXPECT().
			VerifyJWTToken(gomock.Any(), gomock.Any()).
			Return(&testEmail, nil)
		authenticationServiceMock.EXPECT().
			ResendEmailVerification(gomock.Any(), testEmail).
			Return(expectedError)
		loggerMock.EXPECT().Error(expectedError, "Failed to resend email verification")

		response, returnedError := server.ResendEmailVerification(ctx, &pb_authentication.ResendEmailVerificationRequest{})

		assert.Nil(test, response)
		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = Internal server error", returnedError.Error())
	})

	test.Run("ResendEmailVerification_Success", func(test *testing.T) {
		controller, authenticationServiceMock, tokenServiceMock, loggerMock, ctx, server := initialiseTest(test)
		defer controller.Finish()

		testEmail := "example@email.com"
		tokenServiceMock.EXPECT().
			VerifyJWTToken(gomock.Any(), gomock.Any()).
			Return(&testEmail, nil)
		authenticationServiceMock.EXPECT().
			ResendEmailVerification(gomock.Any(), testEmail).
			Return(nil)
		loggerMock.EXPECT().Info("Email verification sent successfully")

		response, returnedError := server.ResendEmailVerification(ctx, &pb_authentication.ResendEmailVerificationRequest{})

		assert.Nil(test, returnedError)
		assert.Equal(test, true, response.Success)
		assert.Equal(test, "Email verification sent successfully", response.Message)
	})

	test.Run("RefreshToken_Success", func(test *testing.T) {
		controller, authenticationServiceMock, _, loggerMock, ctx, server := initialiseTest(test)
		defer controller.Finish()
		testTokenValue := "test-token"
		resultTokens := &model.AuthTokensResponse{
			AuthToken:          "auth-token",
			AuthTokenExpiry:    time.Now(),
			RefreshToken:       "refresh-token",
			RefreshTokenExpiry: time.Now(),
			UserEmail:          "test@user.com",
		}
		authenticationServiceMock.EXPECT().RefreshToken(gomock.Any(),
			testTokenValue,
		).Return(resultTokens, nil)
		loggerMock.EXPECT().Info("Refresh authentication token successful")

		response, returnedError := server.RefreshToken(ctx, &pb_authentication.RefreshTokenRequest{
			Token: testTokenValue,
		})

		assert.Nil(test, returnedError)
		assert.Equal(test, resultTokens.AuthToken, response.AuthToken)
		assert.Equal(test, resultTokens.RefreshToken, response.RefreshToken)
	})

	test.Run("RefreshToken_Error", func(test *testing.T) {
		controller, authenticationServiceMock, _, _, ctx, server := initialiseTest(test)
		defer controller.Finish()
		testTokenValue := "test-token"
		exampleError := errors.New("test-error")
		authenticationServiceMock.EXPECT().RefreshToken(gomock.Any(),
			testTokenValue,
		).Return(nil, exampleError)

		response, returnedError := server.RefreshToken(ctx, &pb_authentication.RefreshTokenRequest{
			Token: testTokenValue,
		})

		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = test-error", returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("RefreshToken_MissingLogger_Error", func(test *testing.T) {
		controller, _, _, _, _, server := initialiseTest(test)
		defer controller.Finish()
		testTokenValue := "test-token"

		response, returnedError := server.RefreshToken(context.Background(), &pb_authentication.RefreshTokenRequest{
			Token: testTokenValue,
		})

		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = Logger not found in context", returnedError.Error())
		assert.Nil(test, response)
	})

	// ForgotPassword
	test.Run("ForgotPassword_Success", func(test *testing.T) {
		controller, authenticationServiceMock, _, loggerMock, ctx, server := initialiseTest(test)
		defer controller.Finish()
		testEmail := "test@email.com"

		authenticationServiceMock.EXPECT().ForgotPassword(gomock.Any(),
			testEmail,
		).Return(nil)
		loggerMock.EXPECT().Info("Forgot password request successful")

		response, returnedError := server.ForgotPassword(ctx, &pb_authentication.ForgotPasswordRequest{
			Email: testEmail,
		})

		assert.Nil(test, returnedError)
		assert.Equal(test, "Forgot password request successful", response.Message)
		assert.True(test, response.Success)
	})

	test.Run("ForgotPassword_Error", func(test *testing.T) {
		controller, authenticationServiceMock, _, loggerMock, ctx, server := initialiseTest(test)
		defer controller.Finish()
		testEmail := "test@email.com"
		exampleError := errors.New("test-error")

		authenticationServiceMock.EXPECT().ForgotPassword(gomock.Any(),
			testEmail,
		).Return(exampleError)
		loggerMock.EXPECT().Error(exampleError, "Forgot password failed")

		response, returnedError := server.ForgotPassword(ctx, &pb_authentication.ForgotPasswordRequest{
			Email: testEmail,
		})

		assert.Error(test, returnedError)
		assert.Nil(test, response)
		assert.Equal(test, "rpc error: code = Internal desc = Internal server error", returnedError.Error())
	})

	test.Run("ForgotPassword_MissingLogger_Error", func(test *testing.T) {
		controller, _, _, _, _, server := initialiseTest(test)
		defer controller.Finish()
		testEmail := "test@email.com"

		response, returnedError := server.ForgotPassword(context.Background(), &pb_authentication.ForgotPasswordRequest{
			Email: testEmail,
		})

		assert.Error(test, returnedError)
		assert.Nil(test, response)
		assert.Equal(test, "rpc error: code = Internal desc = Logger not found in context", returnedError.Error())
	})

	// VerifyResetPasswordToken
	test.Run("VerifyResetPasswordToken_Success", func(test *testing.T) {
		controller, _, tokenServiceMock, loggerMock, ctx, server := initialiseTest(test)
		defer controller.Finish()
		testTokenValue := "test@email.com"

		tokenServiceMock.EXPECT().VerifyResetPasswordToken(
			gomock.Any(),
			testTokenValue,
		).Return(&model.Token{Token: testTokenValue}, nil)
		loggerMock.EXPECT().Info("Verify reset password token successful")

		response, returnedError := server.VerifyResetPasswordToken(ctx, &pb_authentication.VerifyResetPasswordTokenRequest{
			Token: testTokenValue,
		})

		assert.Nil(test, returnedError)
		assert.Equal(test, "Verify reset password token successful", response.Message)
		assert.True(test, response.IsValid)
	})

	test.Run("VerifyResetPasswordToken_Error", func(test *testing.T) {
		controller, _, tokenServiceMock, loggerMock, ctx, server := initialiseTest(test)
		defer controller.Finish()
		testTokenValue := "test@email.com"
		exampleError := errors.New("test-error")

		tokenServiceMock.EXPECT().VerifyResetPasswordToken(gomock.Any(),
			testTokenValue,
		).Return(nil, exampleError)
		loggerMock.EXPECT().Error(exampleError, "Verify reset password token failed")

		response, returnedError := server.VerifyResetPasswordToken(ctx, &pb_authentication.VerifyResetPasswordTokenRequest{
			Token: testTokenValue,
		})

		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = Internal server error", returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("VerifyResetPasswordToken_MissingLogger_Error", func(test *testing.T) {
		controller, _, _, _, _, server := initialiseTest(test)
		defer controller.Finish()
		testTokenValue := "test@email.com"

		response, returnedError := server.VerifyResetPasswordToken(context.Background(), &pb_authentication.VerifyResetPasswordTokenRequest{
			Token: testTokenValue,
		})

		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = Logger not found in context", returnedError.Error())
		assert.Nil(test, response)
	})

	// ResetPassword
	test.Run("ResetPassword_Success", func(test *testing.T) {
		controller, authenticationServiceMock, _, loggerMock, ctx, server := initialiseTest(test)
		defer controller.Finish()
		testTokenValue := "token-value"
		testPassword := "test-password"

		authenticationServiceMock.EXPECT().ResetPassword(
			gomock.Any(),
			testTokenValue,
			testPassword,
		).Return(nil)
		loggerMock.EXPECT().Info("Reset password successful")

		response, returnedError := server.ResetPassword(ctx, &pb_authentication.ResetPasswordRequest{
			Token:       testTokenValue,
			NewPassword: testPassword,
		})

		assert.Nil(test, returnedError)
		assert.Equal(test, "Reset password successful", response.Message)
		assert.True(test, response.Success)
	})

	test.Run("ResetPassword_Error", func(test *testing.T) {
		controller, authenticationServiceMock, _, loggerMock, ctx, server := initialiseTest(test)
		defer controller.Finish()
		testTokenValue := "token-value"
		testPassword := "test-password"
		exampleError := errors.New("test-error")

		authenticationServiceMock.EXPECT().ResetPassword(
			gomock.Any(),
			testTokenValue,
			testPassword,
		).Return(exampleError)
		loggerMock.EXPECT().Error(exampleError, "Reset password failed")

		response, returnedError := server.ResetPassword(ctx, &pb_authentication.ResetPasswordRequest{
			Token:       testTokenValue,
			NewPassword: testPassword,
		})

		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = Internal server error", returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("ResetPassword_MissingLogger_Error", func(test *testing.T) {
		controller, _, _, _, _, server := initialiseTest(test)
		defer controller.Finish()
		testTokenValue := "token-value"
		testPassword := "test-password"

		response, returnedError := server.ResetPassword(context.Background(), &pb_authentication.ResetPasswordRequest{
			Token:       testTokenValue,
			NewPassword: testPassword,
		})

		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = Logger not found in context", returnedError.Error())
		assert.Nil(test, response)
	})
}

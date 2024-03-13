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
	commonToken "github.com/quadev-ltd/qd-common/pkg/token"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	jwtPkg "qd-authentication-api/internal/jwt"
	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/service"
	"qd-authentication-api/internal/service/mock"
	"qd-authentication-api/pb/gen/go/pb_authentication"
)

// TODO: use test suite table driven tests

type GRPCMockParams struct {
	Controller           *gomock.Controller
	MockUserService      *mock.MockUserServicer
	MockTokenService     *mock.MockTokenServicer
	MockPasswordService  *mock.MockPasswordServicer
	MockLogger           *loggerMock.MockLoggerer
	Ctx                  context.Context
	AuthenticationServer AuthenticationServiceServer
}

func initialiseTest(test *testing.T) *GRPCMockParams {
	controller := gomock.NewController(test)

	userServiceMock := mock.NewMockUserServicer(controller)
	tokenServiceMock := mock.NewMockTokenServicer(controller)
	passwordServiceMock := mock.NewMockPasswordServicer(controller)
	loggerMock := loggerMock.NewMockLoggerer(controller)
	ctx := context.WithValue(context.Background(), log.LoggerKey, loggerMock)

	server := AuthenticationServiceServer{
		userService:     userServiceMock,
		tokenService:    tokenServiceMock,
		passwordService: passwordServiceMock,
	}

	return &GRPCMockParams{
		controller,
		userServiceMock,
		tokenServiceMock,
		passwordServiceMock,
		loggerMock,
		ctx,
		server,
	}
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
	exampleClaims := &jwtPkg.TokenClaims{
		UserID: primitive.NewObjectID().Hex(),
		Email:  "test@example.com",
		Type:   commonToken.AccessTokenType,
		Expiry: time.Now().Add(5 * time.Minute),
	}
	test.Run("Registration_Error_Validation", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		mockValidationError := validator.ValidationErrors{
			&mock.CustomValidationError{
				FieldName: "FieldName",
			},
		}

		mocks.MockUserService.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(mockValidationError)

		response, returnedError := mocks.AuthenticationServer.Register(mocks.Ctx, registerRequest)

		assert.Equal(test, "rpc error: code = InvalidArgument desc = Registration failed: FieldName", returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("Registration_Internal_Server_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		mockValidationError := errors.New("some error")

		mocks.MockUserService.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(mockValidationError)

		response, returnedError := mocks.AuthenticationServer.Register(mocks.Ctx, registerRequest)

		assert.Equal(test, "rpc error: code = Internal desc = Registration failed: internal server error", returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("Registration_Error_Email_In_Use", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		mockEmailInUseError := &model.EmailInUseError{Email: "test@example.com"}

		mocks.MockUserService.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(mockEmailInUseError)

		response, returnedError := mocks.AuthenticationServer.Register(mocks.Ctx, registerRequest)

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

		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		response, returnedError := mocks.AuthenticationServer.Register(mocks.Ctx, registerRequestNoDOB)

		assert.Equal(
			test,
			"rpc error: code = InvalidArgument desc = Date of birth was not provided",
			returnedError.Error(),
		)
		assert.Nil(test, response)
	})

	test.Run("Registration_Error_Email_Not_Sent", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		mockServiceError := &service.SendEmailError{Message: "some error"}

		mocks.MockUserService.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(mockServiceError)
		mocks.MockLogger.EXPECT().Info("Registration successful")

		response, returnedError := mocks.AuthenticationServer.Register(mocks.Ctx, registerRequest)

		assert.NoError(
			test,
			returnedError,
		)
		assert.Equal(test, response.Message, "Registration successful. However, verification email failed to send")
		assert.True(test, response.Success)
	})

	test.Run("Registration_Success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		successfulResponse := &pb_authentication.BaseResponse{
			Success: true,
			Message: "Registration successful",
		}

		mocks.MockUserService.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil)
		mocks.MockLogger.EXPECT().Info("Registration successful")

		response, returnedError := mocks.AuthenticationServer.Register(mocks.Ctx, registerRequest)

		assert.Nil(
			test,
			returnedError,
		)
		assert.Equal(test, response.Message, successfulResponse.Message)
		assert.Equal(test, response.Success, successfulResponse.Success)
	})

	test.Run("Email verification internal server error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		mockVerifyEmailError := errors.New("some verification error")

		mocks.MockUserService.EXPECT().
			VerifyEmail(gomock.Any(), verifyEmailRequest.UserId, verifyEmailRequest.VerificationToken).
			Return(mockVerifyEmailError)
		mocks.MockLogger.EXPECT().Error(mockVerifyEmailError, "Email verification failed")

		response, returnedError := mocks.AuthenticationServer.VerifyEmail(mocks.Ctx, verifyEmailRequest)

		assert.Equal(test, status.Error(codes.Internal, "Internal server error"), returnedError)
		assert.Nil(test, response)
	})

	test.Run("Email verification service error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		mockVerifyEmailError := &service.Error{Message: "some error"}

		mocks.MockUserService.EXPECT().
			VerifyEmail(gomock.Any(), verifyEmailRequest.UserId, verifyEmailRequest.VerificationToken).
			Return(mockVerifyEmailError)
		mocks.MockLogger.EXPECT().Error(mockVerifyEmailError, "Email verification failed")

		response, returnedError := mocks.AuthenticationServer.VerifyEmail(mocks.Ctx, verifyEmailRequest)

		assert.Equal(test, status.Error(codes.InvalidArgument, mockVerifyEmailError.Error()), returnedError)
		assert.Nil(test, response)
	})

	test.Run("Verify Email success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		successfulResponse := &pb_authentication.BaseResponse{
			Success: true,
			Message: "Email verified successfully",
		}

		mocks.MockUserService.EXPECT().
			VerifyEmail(gomock.Any(), verifyEmailRequest.UserId, verifyEmailRequest.VerificationToken).
			Return(nil)
		mocks.MockLogger.EXPECT().Info("Email verified successfully")

		response, returnedError := mocks.AuthenticationServer.VerifyEmail(mocks.Ctx, verifyEmailRequest)

		assert.Nil(test, returnedError)
		assert.Equal(test, successfulResponse, response)
	})

	test.Run("Authenticate returns Invalid email or password error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		invalidEmailOrPasswordError := &model.WrongEmailOrPassword{
			FieldName: "Email",
		}
		expectedError := status.Errorf(codes.Unauthenticated, "Invalid email or password")

		mocks.MockUserService.EXPECT().
			Authenticate(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, invalidEmailOrPasswordError)
		mocks.MockLogger.EXPECT().Error(invalidEmailOrPasswordError, "Invalid email or password")

		response, returnedError := mocks.AuthenticationServer.Authenticate(mocks.Ctx, authenticateRequest)

		assert.Equal(test, expectedError.Error(), returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("Authenticate internal server error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		authenticationError := errors.New("some error")
		expectedError := status.Errorf(codes.Internal, "Internal server error")

		mocks.MockUserService.EXPECT().
			Authenticate(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, authenticationError)
		mocks.MockLogger.EXPECT().Error(authenticationError, "Internal error")

		response, returnedError := mocks.AuthenticationServer.Authenticate(mocks.Ctx, authenticateRequest)

		assert.Equal(test, expectedError.Error(), returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("Authenticate success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

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

		mocks.MockUserService.EXPECT().
			Authenticate(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(authenticateResponse, nil)
		mocks.MockLogger.EXPECT().Info("Authentication successful")

		response, returnedError := mocks.AuthenticationServer.Authenticate(mocks.Ctx, authenticateRequest)

		assert.Nil(test, returnedError)
		assert.Equal(test, successfulResponse, response)
	})

	test.Run("ResendEmailVerification_VerifyJWTToken_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		expectedError := errors.New("test-error")

		mocks.MockTokenService.EXPECT().
			VerifyJWTToken(gomock.Any(), gomock.Any()).
			Return(nil, expectedError)
		mocks.MockLogger.EXPECT().Error(expectedError, "Failed to verify JWT token")

		response, returnedError := mocks.AuthenticationServer.ResendEmailVerification(mocks.Ctx, &pb_authentication.ResendEmailVerificationRequest{
			AuthToken: "test-token",
		})

		assert.Nil(test, response)
		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Unauthenticated desc = Invalid JWT token", returnedError.Error())
	})

	test.Run("ResendEmailVerification_ServiceError_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		expectedError := &service.Error{Message: "test-error"}

		mocks.MockTokenService.EXPECT().
			VerifyJWTToken(gomock.Any(), gomock.Any()).
			Return(nil, expectedError)

		response, returnedError := mocks.AuthenticationServer.ResendEmailVerification(mocks.Ctx, &pb_authentication.ResendEmailVerificationRequest{})

		assert.Nil(test, response)
		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = InvalidArgument desc = test-error", returnedError.Error())
	})

	test.Run("ResendEmailVerification_InvalidArgument_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testToken := "test-token"
		userID, err := primitive.ObjectIDFromHex(exampleClaims.UserID)
		if err != nil {
			test.Fatal(err)
		}

		expectedError := &service.Error{Message: "test error"}
		mocks.MockTokenService.EXPECT().
			VerifyJWTToken(gomock.Any(), testToken).
			Return(exampleClaims, nil)
		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(
			gomock.Any(),
			userID,
		).Return(nil, expectedError)
		mocks.MockLogger.EXPECT().Error(expectedError, "Failed to generate email verification token")

		response, returnedError := mocks.AuthenticationServer.ResendEmailVerification(
			mocks.Ctx,
			&pb_authentication.ResendEmailVerificationRequest{
				AuthToken: testToken,
			},
		)

		assert.Nil(test, response)
		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = Internal server error", returnedError.Error())
	})

	test.Run("ResendEmailVerification_InvalidArgument_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testToken := "test-token"
		userID, err := primitive.ObjectIDFromHex(exampleClaims.UserID)
		if err != nil {
			test.Fatal(err)
		}

		expectedError := &service.Error{Message: "test error"}
		mocks.MockTokenService.EXPECT().
			VerifyJWTToken(gomock.Any(), testToken).
			Return(exampleClaims, nil)
		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(
			gomock.Any(),
			userID,
		).Return(&testToken, nil)
		mocks.MockUserService.EXPECT().
			ResendEmailVerification(gomock.Any(), exampleClaims.Email, testToken).
			Return(expectedError)

		response, returnedError := mocks.AuthenticationServer.ResendEmailVerification(
			mocks.Ctx,
			&pb_authentication.ResendEmailVerificationRequest{
				AuthToken: testToken,
			},
		)

		assert.Nil(test, response)
		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = InvalidArgument desc = test error", returnedError.Error())
	})

	test.Run("ResendEmailVerification_InternalServerError", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testToken := "test-token"
		userID, err := primitive.ObjectIDFromHex(exampleClaims.UserID)
		if err != nil {
			test.Fatal(err)
		}

		expectedError := errors.New("test error")
		mocks.MockTokenService.EXPECT().
			VerifyJWTToken(gomock.Any(), testToken).
			Return(exampleClaims, nil)
		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(
			gomock.Any(),
			userID,
		).Return(&testToken, nil)
		mocks.MockUserService.EXPECT().
			ResendEmailVerification(gomock.Any(), exampleClaims.Email, testToken).
			Return(expectedError)
		mocks.MockLogger.EXPECT().Error(expectedError, "Failed to resend email verification")

		response, returnedError := mocks.AuthenticationServer.ResendEmailVerification(
			mocks.Ctx,
			&pb_authentication.ResendEmailVerificationRequest{
				AuthToken: testToken,
			},
		)

		assert.Nil(test, response)
		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = Internal server error", returnedError.Error())
	})

	test.Run("ResendEmailVerification_Success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testToken := "test-token"
		userID, err := primitive.ObjectIDFromHex(exampleClaims.UserID)
		if err != nil {
			test.Fatal(err)
		}

		mocks.MockTokenService.EXPECT().
			VerifyJWTToken(gomock.Any(), gomock.Any()).
			Return(exampleClaims, nil)
		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(
			gomock.Any(),
			userID,
		).Return(&testToken, nil)
		mocks.MockUserService.EXPECT().
			ResendEmailVerification(gomock.Any(), exampleClaims.Email, testToken).
			Return(nil)
		mocks.MockLogger.EXPECT().Info("Email verification sent successfully")

		response, returnedError := mocks.AuthenticationServer.ResendEmailVerification(
			mocks.Ctx,
			&pb_authentication.ResendEmailVerificationRequest{
				AuthToken: testToken,
			},
		)

		assert.Nil(test, returnedError)
		assert.Equal(test, true, response.Success)
		assert.Equal(test, "Email verification sent successfully", response.Message)
	})

	test.Run("RefreshToken_Success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "test-token"
		resultTokens := &model.AuthTokensResponse{
			AuthToken:          "auth-token",
			AuthTokenExpiry:    time.Now(),
			RefreshToken:       "refresh-token",
			RefreshTokenExpiry: time.Now(),
			UserEmail:          "test@user.com",
		}
		mocks.MockUserService.EXPECT().RefreshToken(gomock.Any(),
			testTokenValue,
		).Return(resultTokens, nil)
		mocks.MockLogger.EXPECT().Info("Refresh authentication token successful")

		response, returnedError := mocks.AuthenticationServer.RefreshToken(mocks.Ctx, &pb_authentication.RefreshTokenRequest{
			Token: testTokenValue,
		})

		assert.Nil(test, returnedError)
		assert.Equal(test, resultTokens.AuthToken, response.AuthToken)
		assert.Equal(test, resultTokens.RefreshToken, response.RefreshToken)
	})

	test.Run("RefreshToken_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "test-token"
		exampleError := errors.New("test-error")
		mocks.MockUserService.EXPECT().RefreshToken(gomock.Any(),
			testTokenValue,
		).Return(nil, exampleError)

		response, returnedError := mocks.AuthenticationServer.RefreshToken(mocks.Ctx, &pb_authentication.RefreshTokenRequest{
			Token: testTokenValue,
		})

		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = test-error", returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("RefreshToken_MissingLogger_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "test-token"

		response, returnedError := mocks.AuthenticationServer.RefreshToken(context.Background(), &pb_authentication.RefreshTokenRequest{
			Token: testTokenValue,
		})

		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = Logger not found in context", returnedError.Error())
		assert.Nil(test, response)
	})

	// ForgotPassword
	test.Run("ForgotPassword_Success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testEmail := "test@email.com"

		mocks.MockPasswordService.EXPECT().ForgotPassword(
			gomock.Any(),
			testEmail,
		).Return(nil)
		mocks.MockLogger.EXPECT().Info("Forgot password request successful")

		response, returnedError := mocks.AuthenticationServer.ForgotPassword(mocks.Ctx, &pb_authentication.ForgotPasswordRequest{
			Email: testEmail,
		})

		assert.Nil(test, returnedError)
		assert.Equal(test, "Forgot password request successful", response.Message)
		assert.True(test, response.Success)
	})

	test.Run("ForgotPassword_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testEmail := "test@email.com"
		exampleError := errors.New("test-error")

		mocks.MockPasswordService.EXPECT().ForgotPassword(gomock.Any(),
			testEmail,
		).Return(exampleError)
		mocks.MockLogger.EXPECT().Error(exampleError, "Forgot password failed")

		response, returnedError := mocks.AuthenticationServer.ForgotPassword(mocks.Ctx, &pb_authentication.ForgotPasswordRequest{
			Email: testEmail,
		})

		assert.Error(test, returnedError)
		assert.Nil(test, response)
		assert.Equal(test, "rpc error: code = Internal desc = Internal server error", returnedError.Error())
	})

	test.Run("ForgotPassword_MissingLogger_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testEmail := "test@email.com"

		response, returnedError := mocks.AuthenticationServer.ForgotPassword(context.Background(), &pb_authentication.ForgotPasswordRequest{
			Email: testEmail,
		})

		assert.Error(test, returnedError)
		assert.Nil(test, response)
		assert.Equal(test, "rpc error: code = Internal desc = Logger not found in context", returnedError.Error())
	})

	// VerifyResetPasswordToken
	test.Run("VerifyResetPasswordToken_Success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "test@email.com"
		userID := primitive.NewObjectID().Hex()

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(
			gomock.Any(),
			userID,
			testTokenValue,
		).Return(&model.Token{TokenHash: testTokenValue}, nil)
		mocks.MockLogger.EXPECT().Info("Verify reset password token successful")

		response, returnedError := mocks.AuthenticationServer.VerifyResetPasswordToken(mocks.Ctx, &pb_authentication.VerifyResetPasswordTokenRequest{
			UserId: userID,
			Token:  testTokenValue,
		})

		assert.Nil(test, returnedError)
		assert.Equal(test, "Verify reset password token successful", response.Message)
		assert.True(test, response.IsValid)
	})

	test.Run("VerifyResetPasswordToken_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "test@email.com"
		exampleError := errors.New("test-error")
		userID := primitive.NewObjectID().Hex()

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(
			gomock.Any(),
			userID,
			testTokenValue,
		).Return(nil, exampleError)
		mocks.MockLogger.EXPECT().Error(exampleError, "Verify reset password token failed")

		response, returnedError := mocks.AuthenticationServer.VerifyResetPasswordToken(mocks.Ctx, &pb_authentication.VerifyResetPasswordTokenRequest{
			UserId: userID,
			Token:  testTokenValue,
		})

		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = Internal server error", returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("VerifyResetPasswordToken_MissingLogger_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "test@email.com"
		userID := primitive.NewObjectID().Hex()

		response, returnedError := mocks.AuthenticationServer.VerifyResetPasswordToken(context.Background(), &pb_authentication.VerifyResetPasswordTokenRequest{
			UserId: userID,
			Token:  testTokenValue,
		})

		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = Logger not found in context", returnedError.Error())
		assert.Nil(test, response)
	})

	// ResetPassword
	test.Run("ResetPassword_Success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "token-value"
		testPassword := "test-password"
		userID := primitive.NewObjectID().Hex()
		mocks.MockPasswordService.EXPECT().ResetPassword(
			gomock.Any(),
			userID,
			testTokenValue,
			testPassword,
		).Return(nil)
		mocks.MockLogger.EXPECT().Info("Reset password successful")

		response, returnedError := mocks.AuthenticationServer.ResetPassword(mocks.Ctx, &pb_authentication.ResetPasswordRequest{
			UserId:      userID,
			Token:       testTokenValue,
			NewPassword: testPassword,
		})

		assert.Nil(test, returnedError)
		assert.Equal(test, "Reset password successful", response.Message)
		assert.True(test, response.Success)
	})

	test.Run("ResetPassword_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "token-value"
		testPassword := "test-password"
		exampleError := errors.New("test-error")
		userID := primitive.NewObjectID().Hex()
		mocks.MockPasswordService.EXPECT().ResetPassword(
			gomock.Any(),
			userID,
			testTokenValue,
			testPassword,
		).Return(exampleError)
		mocks.MockLogger.EXPECT().Error(exampleError, "Reset password failed")

		response, returnedError := mocks.AuthenticationServer.ResetPassword(mocks.Ctx, &pb_authentication.ResetPasswordRequest{
			UserId:      userID,
			Token:       testTokenValue,
			NewPassword: testPassword,
		})

		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = Internal server error", returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("ResetPassword_MissingLogger_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "token-value"
		testPassword := "test-password"

		response, returnedError := mocks.AuthenticationServer.ResetPassword(context.Background(), &pb_authentication.ResetPasswordRequest{
			Token:       testTokenValue,
			NewPassword: testPassword,
		})

		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = Logger not found in context", returnedError.Error())
		assert.Nil(test, response)
	})

	// GetUserProfile
	test.Run("GetUserProfile_Success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "token-value"
		user := model.NewUser()
		userObjID, err := primitive.ObjectIDFromHex(exampleClaims.UserID)
		if err != nil {
			test.Fatal(err)
		}
		user.ID = userObjID

		mocks.MockTokenService.EXPECT().VerifyJWTToken(
			gomock.Any(),
			testTokenValue,
		).Return(
			exampleClaims,
			nil,
		)
		mocks.MockUserService.EXPECT().GetUserProfile(
			gomock.Any(),
			exampleClaims.UserID,
		).Return(
			user,
			nil,
		)
		mocks.MockLogger.EXPECT().Info("Get user profile successful")

		getUserProfileResponse, err := mocks.AuthenticationServer.GetUserProfile(
			mocks.Ctx,
			&pb_authentication.GetUserProfileRequest{
				AuthToken: testTokenValue,
			},
		)

		assert.NoError(test, err)
		assert.Equal(test, user.ID.Hex(), getUserProfileResponse.User.UserId)
		assert.Equal(test, user.Email, getUserProfileResponse.User.Email)
		assert.Equal(test, user.FirstName, getUserProfileResponse.User.FirstName)
		assert.Equal(test, user.LastName, getUserProfileResponse.User.LastName)
		assert.Equal(test, user.DateOfBirth.Unix(), getUserProfileResponse.User.DateOfBirth.AsTime().Unix())
		assert.Equal(test, user.RegistrationDate.Unix(), getUserProfileResponse.User.RegistrationDate.AsTime().Unix())
	})

	test.Run("GetUserProfile_SerService_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "token-value"
		user := model.NewUser()
		mockedError := &service.Error{
			Message: "test-error",
		}

		userObjID, err := primitive.ObjectIDFromHex(exampleClaims.UserID)
		if err != nil {
			test.Fatal(err)
		}
		user.ID = userObjID

		mocks.MockTokenService.EXPECT().VerifyJWTToken(
			gomock.Any(),
			testTokenValue,
		).Return(
			exampleClaims,
			nil,
		)
		mocks.MockUserService.EXPECT().GetUserProfile(
			gomock.Any(),
			exampleClaims.UserID,
		).Return(
			nil,
			mockedError,
		)

		getUserProfileResponse, err := mocks.AuthenticationServer.GetUserProfile(
			mocks.Ctx,
			&pb_authentication.GetUserProfileRequest{
				AuthToken: testTokenValue,
			},
		)

		assert.Error(test, err)
		assert.Nil(test, getUserProfileResponse)
		assert.EqualError(test, err, "rpc error: code = InvalidArgument desc = test-error")
	})

	test.Run("GetUserProfile_General_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "token-value"
		user := model.NewUser()
		mockedError := errors.New("test-error")

		userObjID, err := primitive.ObjectIDFromHex(exampleClaims.UserID)
		if err != nil {
			test.Fatal(err)
		}
		user.ID = userObjID

		mocks.MockTokenService.EXPECT().VerifyJWTToken(
			gomock.Any(),
			testTokenValue,
		).Return(
			exampleClaims,
			nil,
		)
		mocks.MockUserService.EXPECT().GetUserProfile(
			gomock.Any(),
			exampleClaims.UserID,
		).Return(
			nil,
			mockedError,
		)

		getUserProfileResponse, err := mocks.AuthenticationServer.GetUserProfile(
			mocks.Ctx,
			&pb_authentication.GetUserProfileRequest{
				AuthToken: testTokenValue,
			},
		)

		assert.Error(test, err)
		assert.Nil(test, getUserProfileResponse)
		assert.EqualError(test, err, "rpc error: code = Internal desc = Internal server error")
	})

	test.Run("GetUserProfile_TokenService_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "token-value"
		user := model.NewUser()
		mockedError := &service.Error{
			Message: "test-error",
		}

		userObjID, err := primitive.ObjectIDFromHex(exampleClaims.UserID)
		if err != nil {
			test.Fatal(err)
		}
		user.ID = userObjID

		mocks.MockTokenService.EXPECT().VerifyJWTToken(
			gomock.Any(),
			testTokenValue,
		).Return(
			nil,
			mockedError,
		)

		getUserProfileResponse, err := mocks.AuthenticationServer.GetUserProfile(
			mocks.Ctx,
			&pb_authentication.GetUserProfileRequest{
				AuthToken: testTokenValue,
			},
		)

		assert.Error(test, err)
		assert.Nil(test, getUserProfileResponse)
		assert.EqualError(test, err, "rpc error: code = Unauthenticated desc = test-error")
	})

	test.Run("GetUserProfile_TokenGeneral_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "token-value"
		user := model.NewUser()
		mockedError := errors.New("test-error")

		userObjID, err := primitive.ObjectIDFromHex(exampleClaims.UserID)
		if err != nil {
			test.Fatal(err)
		}
		user.ID = userObjID

		mocks.MockTokenService.EXPECT().VerifyJWTToken(
			gomock.Any(),
			testTokenValue,
		).Return(
			nil,
			mockedError,
		)

		getUserProfileResponse, err := mocks.AuthenticationServer.GetUserProfile(
			mocks.Ctx,
			&pb_authentication.GetUserProfileRequest{
				AuthToken: testTokenValue,
			},
		)

		assert.Error(test, err)
		assert.Nil(test, getUserProfileResponse)
		assert.EqualError(test, err, "rpc error: code = Unauthenticated desc = Invalid JWT token")
	})

	test.Run("UpdateUserProfile_Success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "token-value"
		user := model.NewUser()
		userObjID, err := primitive.ObjectIDFromHex(exampleClaims.UserID)
		if err != nil {
			test.Fatal(err)
		}
		user.ID = userObjID
		newFirstName := "John"
		newLastName := "Doe"
		newDOB := timestamppb.Now()
		user.FirstName = newFirstName
		user.LastName = newLastName
		user.DateOfBirth = newDOB.AsTime()
		updateRequest := &pb_authentication.UpdateUserProfileRequest{
			AuthToken:   testTokenValue,
			FirstName:   newFirstName,
			LastName:    newLastName,
			DateOfBirth: newDOB,
		}

		mocks.MockTokenService.EXPECT().VerifyJWTToken(
			gomock.Any(),
			testTokenValue,
		).Return(
			exampleClaims,
			nil,
		)
		mocks.MockUserService.EXPECT().UpdateProfileDetails(
			gomock.Any(),
			exampleClaims.UserID,
			gomock.Eq(updateRequest),
		).Return(
			user,
			nil,
		)
		mocks.MockLogger.EXPECT().Info("Update user profile successful")

		updateUserProfileResponse, err := mocks.AuthenticationServer.UpdateUserProfile(
			mocks.Ctx,
			updateRequest,
		)

		assert.NoError(test, err)
		assert.Equal(test, user.ID.Hex(), updateUserProfileResponse.User.UserId)
		assert.Equal(test, user.Email, updateUserProfileResponse.User.Email)
		assert.Equal(test, newFirstName, updateUserProfileResponse.User.FirstName)
		assert.Equal(test, newLastName, updateUserProfileResponse.User.LastName)
		assert.Equal(test, newDOB, updateUserProfileResponse.User.DateOfBirth)
	})

	test.Run("UpdateUserProfile_Update_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		mockedError := errors.New("test-error")
		testTokenValue := "token-value"
		newFirstName := "John"
		newLastName := "Doe"
		newDOB := timestamppb.Now()
		updateRequest := &pb_authentication.UpdateUserProfileRequest{
			AuthToken:   testTokenValue,
			FirstName:   newFirstName,
			LastName:    newLastName,
			DateOfBirth: newDOB,
		}

		mocks.MockTokenService.EXPECT().VerifyJWTToken(
			gomock.Any(),
			testTokenValue,
		).Return(
			exampleClaims,
			nil,
		)
		mocks.MockUserService.EXPECT().UpdateProfileDetails(
			gomock.Any(),
			exampleClaims.UserID,
			gomock.Eq(updateRequest),
		).Return(
			nil,
			mockedError,
		)

		updateUserProfileResponse, err := mocks.AuthenticationServer.UpdateUserProfile(
			mocks.Ctx,
			updateRequest,
		)

		assert.Error(test, err)
		assert.Nil(test, updateUserProfileResponse)
		assert.EqualError(test, err, "rpc error: code = Internal desc = Internal server error")
	})
}

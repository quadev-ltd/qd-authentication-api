package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/golang/mock/gomock"
	commonJWT "github.com/quadev-ltd/qd-common/pkg/jwt"
	"github.com/quadev-ltd/qd-common/pkg/log"
	loggerMock "github.com/quadev-ltd/qd-common/pkg/log/mock"
	"github.com/stretchr/testify/assert"

	jwtManagerMock "qd-authentication-api/internal/jwt/mock"
	"qd-authentication-api/internal/model"
	repositoryMock "qd-authentication-api/internal/repository/mock"
)

type TokenAuthenServiceMockedParams struct {
	MockTokenRepo  repositoryMock.MockTokenRepositoryer
	MockJWTManager jwtManagerMock.MockManagerer
	TokenService   TokenServicer
}

func createTokenService(controller *gomock.Controller) *TokenAuthenServiceMockedParams {
	mockTokenRepo := repositoryMock.NewMockTokenRepositoryer(controller)
	mockJWTManager := jwtManagerMock.NewMockManagerer(controller)
	tokenService := NewTokenService(
		mockTokenRepo,
		mockJWTManager,
	)

	return &TokenAuthenServiceMockedParams{
		*mockTokenRepo,
		*mockJWTManager,
		tokenService,
	}
}

func TestTokenService(test *testing.T) {
	// VerifyTokenAndDecodeEmail
	test.Run("VerifyTokenAndDecodeEmail_VerifyToken_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createTokenService(controller)

		token := "invalid-token"
		mockedError := errors.New("Token verification failed")

		mocks.MockJWTManager.EXPECT().VerifyToken(token).Return(nil, mockedError)

		// Act
		email, err := mocks.TokenService.VerifyJWTTokenAndExtractEmail(context.Background(), token)

		// Assert
		assert.Error(test, err)
		assert.Nil(test, email)
		assert.Equal(test, "Error verifying token: Token verification failed", err.Error())
	})

	test.Run("VerifyTokenAndDecodeEmail_GetEmailFromToken_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createTokenService(controller)

		token := "valid-token"
		mockedError := errors.New("Error decoding email")

		mocks.MockJWTManager.EXPECT().VerifyToken(token).Return(&jwt.Token{}, nil)
		mocks.MockJWTManager.EXPECT().GetEmailFromToken(gomock.Any()).Return(nil, mockedError)

		// Act
		email, err := mocks.TokenService.VerifyJWTTokenAndExtractEmail(context.Background(), token)

		// Assert
		assert.Error(test, err)
		assert.Nil(test, email)
		assert.Equal(test, "Error getting email from token: Error decoding email", err.Error())
	})

	test.Run("VerifyTokenAndDecodeEmail_Success", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createTokenService(controller)

		exampleEmail := "example@email.com"
		token := "valid-token"
		jwtToken := jwt.Token{}
		mocks.MockJWTManager.EXPECT().VerifyToken(token).Return(&jwtToken, nil)
		mocks.MockJWTManager.EXPECT().GetEmailFromToken(&jwtToken).Return(&exampleEmail, nil)

		// Act
		email, err := mocks.TokenService.VerifyJWTTokenAndExtractEmail(context.Background(), token)

		// Assert
		assert.NoError(test, err)
		assert.NotNil(test, email)
		assert.Equal(test, exampleEmail, *email)
	})

	// RefreshToken
	test.Run("VerifyJWTToken_VerifyToken_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createTokenService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		token := "test_token"
		errorMessage := "Database error"
		errorExample := errors.New(errorMessage)

		mocks.MockJWTManager.EXPECT().VerifyToken(gomock.Any()).Return(nil, errorExample)
		logMock.EXPECT().Error(errorExample, "Error verifying refresh token")

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		// Test RefreshToken
		user, err := mocks.TokenService.VerifyJWTToken(ctx, token)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Invalid or expired refresh token", err.Error())
		assert.Nil(test, user)
	})

	test.Run("VerifyJWTToken_GetByEmail_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createTokenService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		token := "test_token"
		errorMessage := "Database error"
		errorExample := errors.New(errorMessage)

		mocks.MockJWTManager.EXPECT().VerifyToken(token).Return(&jwt.Token{}, nil)
		mocks.MockJWTManager.EXPECT().GetEmailFromToken(gomock.Any()).Return(nil, errorExample)
		logMock.EXPECT().Error(errorExample, "Error getting email from token")

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		// Test RefreshToken
		user, err := mocks.TokenService.VerifyJWTToken(ctx, token)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error getting email from token", err.Error())
		assert.Nil(test, user)
	})

	test.Run("VerifyJWTToken_Success", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createTokenService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		jwtToken := &jwt.Token{}
		email := "email@example.com"
		user := model.NewUser()

		mocks.MockJWTManager.EXPECT().VerifyToken(refreshTokenValue).Return(jwtToken, nil)
		mocks.MockJWTManager.EXPECT().GetEmailFromToken(jwtToken).Return(&email, nil)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		// Test RefreshToken
		resultUser, resultError := mocks.TokenService.VerifyJWTToken(ctx, refreshTokenValue)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, resultUser)
		assert.Equal(test, testEmail, user.Email)
	})

	// VerifyResetPasswordToken
	test.Run("VerifyResetPasswordToken_Success", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createTokenService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		testTokenValue := "test-token"
		testToken := model.NewToken(testTokenValue)
		testToken.Type = commonJWT.ResetPasswordTokenType

		mocks.MockTokenRepo.EXPECT().GetByToken(gomock.Any(), testTokenValue).Return(testToken, nil)

		// Act
		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)
		token, err := mocks.TokenService.VerifyResetPasswordToken(ctx, testTokenValue)

		// Assert
		assert.NoError(test, err)
		assert.NotNil(test, token)
		assert.Equal(test, testTokenValue, token.Token)
	})

	test.Run("VerifyResetPasswordToken_Expired_Error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createTokenService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		testTokenValue := "test-token"
		testToken := model.NewToken(testTokenValue)
		testToken.Type = commonJWT.ResetPasswordTokenType
		testToken.ExpiresAt = time.Now().Add(-1 * time.Second)

		mocks.MockTokenRepo.EXPECT().GetByToken(gomock.Any(), testTokenValue).Return(testToken, nil)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		// Act
		token, err := mocks.TokenService.VerifyResetPasswordToken(ctx, testTokenValue)

		// Assert
		assert.Nil(test, token)
		assert.Error(test, err)
		assert.Equal(test, "Token expired", err.Error())
	})

	test.Run("VerifyResetPasswordToken_TokenType_Error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createTokenService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		testTokenValue := "test-token"
		testToken := model.NewToken(testTokenValue)

		mocks.MockTokenRepo.EXPECT().GetByToken(gomock.Any(), testTokenValue).Return(testToken, nil)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		// Act
		token, err := mocks.TokenService.VerifyResetPasswordToken(ctx, testTokenValue)

		// Assert
		assert.Nil(test, token)
		assert.Error(test, err)
		assert.Equal(test, "Invalid token type", err.Error())
	})

	test.Run("VerifyResetPasswordToken_MissingToken_Error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createTokenService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		testTokenValue := "test-token"
		exampleError := errors.New("test-error")

		mocks.MockTokenRepo.EXPECT().GetByToken(gomock.Any(), testTokenValue).Return(nil, exampleError)
		logMock.EXPECT().Error(exampleError, "Error getting token by its value")
		// Act
		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)
		token, err := mocks.TokenService.VerifyResetPasswordToken(ctx, testTokenValue)

		// Assert
		assert.Nil(test, token)
		assert.Error(test, err)
		assert.Equal(test, "Invalid token", err.Error())
	})
}

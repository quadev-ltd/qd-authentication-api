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
	"go.mongodb.org/mongo-driver/bson/primitive"

	jwtManagerMock "qd-authentication-api/internal/jwt/mock"
	"qd-authentication-api/internal/model"
	repositoryMock "qd-authentication-api/internal/repository/mock"
)

type TokenAuthenServiceMockedParams struct {
	MockTokenRepo  repositoryMock.MockTokenRepositoryer
	MockJWTManager jwtManagerMock.MockManagerer
	MockLogger     *loggerMock.MockLoggerer
	TokenService   TokenServicer
	Controller     *gomock.Controller
	Ctx            context.Context
}

func createTokenService(test *testing.T) *TokenAuthenServiceMockedParams {
	controller := gomock.NewController(test)
	mockTokenRepo := repositoryMock.NewMockTokenRepositoryer(controller)
	mockJWTManager := jwtManagerMock.NewMockManagerer(controller)
	mockLogger := loggerMock.NewMockLoggerer(controller)
	tokenService := NewTokenService(
		mockTokenRepo,
		mockJWTManager,
	)
	ctx := context.WithValue(context.Background(), log.LoggerKey, mockLogger)

	return &TokenAuthenServiceMockedParams{
		*mockTokenRepo,
		*mockJWTManager,
		mockLogger,
		tokenService,
		controller,
		ctx,
	}
}

func TestTokenService(test *testing.T) {
	// VerifyJWTToken
	test.Run("VerifyJWTToken_VerifyToken_Error", func(test *testing.T) {
		// Arrange
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		token := "invalid-token"

		mocks.MockJWTManager.EXPECT().VerifyToken(token).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error verifying refresh token")

		// Act
		email, err := mocks.TokenService.VerifyJWTToken(mocks.Ctx, token)

		// Assert
		assert.Error(test, err)
		assert.Nil(test, email)
		assert.Equal(test, "Invalid or expired refresh token", err.Error())
	})

	test.Run("VerifyJWTToken_GetEmailFromToken_Error", func(test *testing.T) {
		// Arrange
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		token := "valid-token"

		mocks.MockJWTManager.EXPECT().VerifyToken(token).Return(&jwt.Token{}, nil)
		mocks.MockJWTManager.EXPECT().GetEmailFromToken(gomock.Any()).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error getting email from token")

		// Act
		email, err := mocks.TokenService.VerifyJWTToken(mocks.Ctx, token)

		// Assert
		assert.Error(test, err)
		assert.Nil(test, email)
		assert.Equal(test, "Error getting email from token", err.Error())
	})

	test.Run("VerifyJWTToken_Success", func(test *testing.T) {
		// Arrange
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		exampleEmail := "example@email.com"
		token := "valid-token"
		jwtToken := jwt.Token{}
		mocks.MockJWTManager.EXPECT().VerifyToken(token).Return(&jwtToken, nil)
		mocks.MockJWTManager.EXPECT().GetEmailFromToken(&jwtToken).Return(&exampleEmail, nil)

		// Act
		email, err := mocks.TokenService.VerifyJWTToken(mocks.Ctx, token)

		// Assert
		assert.NoError(test, err)
		assert.NotNil(test, email)
		assert.Equal(test, exampleEmail, *email)
	})

	// RefreshToken
	test.Run("VerifyJWTToken_VerifyToken_error", func(test *testing.T) {
		// Arrange
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		token := "test_token"
		errorMessage := "Database error"
		errorExample := errors.New(errorMessage)

		mocks.MockJWTManager.EXPECT().VerifyToken(gomock.Any()).Return(nil, errorExample)
		mocks.MockLogger.EXPECT().Error(errorExample, "Error verifying refresh token")

		// Test RefreshToken
		user, err := mocks.TokenService.VerifyJWTToken(mocks.Ctx, token)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Invalid or expired refresh token", err.Error())
		assert.Nil(test, user)
	})

	test.Run("VerifyJWTToken_GetByEmail_error", func(test *testing.T) {
		// Arrange
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		token := "test_token"
		errorMessage := "Database error"
		errorExample := errors.New(errorMessage)

		mocks.MockJWTManager.EXPECT().VerifyToken(token).Return(&jwt.Token{}, nil)
		mocks.MockJWTManager.EXPECT().GetEmailFromToken(gomock.Any()).Return(nil, errorExample)
		mocks.MockLogger.EXPECT().Error(errorExample, "Error getting email from token")

		// Test RefreshToken
		user, err := mocks.TokenService.VerifyJWTToken(mocks.Ctx, token)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error getting email from token", err.Error())
		assert.Nil(test, user)
	})

	test.Run("VerifyJWTToken_Success", func(test *testing.T) {
		// Arrange
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		jwtToken := &jwt.Token{}
		email := "email@example.com"
		user := model.NewUser()

		mocks.MockJWTManager.EXPECT().VerifyToken(refreshTokenValue).Return(jwtToken, nil)
		mocks.MockJWTManager.EXPECT().GetEmailFromToken(jwtToken).Return(&email, nil)

		// Test RefreshToken
		resultUser, resultError := mocks.TokenService.VerifyJWTToken(mocks.Ctx, refreshTokenValue)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, resultUser)
		assert.Equal(test, testEmail, user.Email)
	})

	// VerifyResetPasswordToken
	test.Run("VerifyResetPasswordToken_Success", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testTokenValue := "test-token"
		testToken := model.NewToken(testTokenValue)
		testToken.Type = commonJWT.ResetPasswordTokenType

		mocks.MockTokenRepo.EXPECT().GetByToken(gomock.Any(), testTokenValue).Return(testToken, nil)

		// Act
		token, err := mocks.TokenService.VerifyResetPasswordToken(mocks.Ctx, testTokenValue)

		// Assert
		assert.NoError(test, err)
		assert.NotNil(test, token)
		assert.Equal(test, testTokenValue, token.Token)
	})

	test.Run("VerifyResetPasswordToken_Expired_Error", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testTokenValue := "test-token"
		testToken := model.NewToken(testTokenValue)
		testToken.Type = commonJWT.ResetPasswordTokenType
		testToken.ExpiresAt = time.Now().Add(-1 * time.Second)

		mocks.MockTokenRepo.EXPECT().GetByToken(gomock.Any(), testTokenValue).Return(testToken, nil)

		// Act
		token, err := mocks.TokenService.VerifyResetPasswordToken(mocks.Ctx, testTokenValue)

		// Assert
		assert.Nil(test, token)
		assert.Error(test, err)
		assert.Equal(test, "Token expired", err.Error())
	})

	test.Run("VerifyResetPasswordToken_TokenType_Error", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testTokenValue := "test-token"
		testToken := model.NewToken(testTokenValue)

		mocks.MockTokenRepo.EXPECT().GetByToken(gomock.Any(), testTokenValue).Return(testToken, nil)

		// Act
		token, err := mocks.TokenService.VerifyResetPasswordToken(mocks.Ctx, testTokenValue)

		// Assert
		assert.Nil(test, token)
		assert.Error(test, err)
		assert.Equal(test, "Invalid token type", err.Error())
	})

	test.Run("VerifyResetPasswordToken_MissingToken_Error", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testTokenValue := "test-token"
		exampleError := errors.New("test-error")

		mocks.MockTokenRepo.EXPECT().GetByToken(gomock.Any(), testTokenValue).Return(nil, exampleError)
		mocks.MockLogger.EXPECT().Error(exampleError, "Error getting token by its value")
		// Act
		token, err := mocks.TokenService.VerifyResetPasswordToken(mocks.Ctx, testTokenValue)

		// Assert
		assert.Nil(test, token)
		assert.Error(test, err)
		assert.Equal(test, "Invalid token", err.Error())
	})

	// GenerateEmailVerificationToken
	test.Run("GenerateEmailVerificationToken_Success", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		mocks.MockTokenRepo.EXPECT().InsertToken(
			gomock.Any(),
			gomock.Any(),
		).Return(primitive.NewObjectID(), nil)

		token, resultError := mocks.TokenService.GenerateEmailVerificationToken(mocks.Ctx, userID)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, token)
	})

	test.Run("GenerateEmailVerificationToken_Insert_Error", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		mocks.MockTokenRepo.EXPECT().InsertToken(
			gomock.Any(),
			gomock.Any(),
		).Return(nil, errExample)

		token, resultError := mocks.TokenService.GenerateEmailVerificationToken(mocks.Ctx, userID)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, token)
	})

	// GeneratePasswordResetToken
	test.Run("GeneratePasswordResetToken_Success", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		mocks.MockTokenRepo.EXPECT().InsertToken(
			gomock.Any(),
			gomock.Any(),
		).Return(primitive.NewObjectID(), nil)

		token, resultError := mocks.TokenService.GeneratePasswordResetToken(mocks.Ctx, userID)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, token)
	})

	test.Run("GeneratePasswordResetToken_Insert_Error", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		mocks.MockTokenRepo.EXPECT().InsertToken(
			gomock.Any(),
			gomock.Any(),
		).Return(nil, errExample)

		token, resultError := mocks.TokenService.GeneratePasswordResetToken(mocks.Ctx, userID)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, token)
	})

	// VerifyEmailVerificationToken
	test.Run("VerifyEmailVerificationToken_Expired_Success", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testToken := model.NewToken(testTokenValue)
		testToken.ExpiresAt = time.Now().Add(10 * time.Second)

		mocks.MockTokenRepo.EXPECT().GetByToken(
			gomock.Any(),
			testTokenValue,
		).Return(testToken, nil)

		token, err := mocks.TokenService.VerifyEmailVerificationToken(mocks.Ctx, testTokenValue)

		// Assert
		assert.NotNil(test, token)
		assert.NoError(test, err)
		assert.Equal(test, testToken.Token, token.Token)
		assert.Equal(test, testToken.Type, token.Type)
		assert.Equal(test, testToken.Revoked, token.Revoked)
	})
	test.Run("VerifyEmailVerificationToken_Expired_Error", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		expiredToken := model.NewToken(testTokenValue)
		expiredToken.ExpiresAt = time.Now().Add(-1 * time.Second)

		mocks.MockTokenRepo.EXPECT().GetByToken(
			gomock.Any(),
			testTokenValue,
		).Return(expiredToken, nil)

		token, err := mocks.TokenService.VerifyEmailVerificationToken(mocks.Ctx, testTokenValue)

		// Assert
		assert.NotNil(test, err)
		assert.Nil(test, token)
		assert.Error(test, err)
		assert.IsType(test, &Error{}, err)
		assert.Contains(test, err.Error(), "Token expired")
	})

	test.Run("VerifyEmailVerificationToken_Type_Error", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testToken := model.NewToken(testTokenValue)
		testToken.Type = commonJWT.ResetPasswordTokenType

		mocks.MockTokenRepo.EXPECT().GetByToken(
			gomock.Any(),
			testTokenValue,
		).Return(testToken, nil)

		token, err := mocks.TokenService.VerifyEmailVerificationToken(mocks.Ctx, testTokenValue)

		// Assert
		assert.NotNil(test, err)
		assert.Nil(test, token)
		assert.Error(test, err)
		assert.IsType(test, &Error{}, err)
		assert.Contains(test, err.Error(), "Invalid token type")
	})

	test.Run("VerifyEmailVerificationToken_Value_Error", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testToken := model.NewToken(testTokenValue)
		testToken.Type = commonJWT.ResetPasswordTokenType

		mocks.MockTokenRepo.EXPECT().GetByToken(
			gomock.Any(),
			testTokenValue,
		).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error getting token by its value")

		token, err := mocks.TokenService.VerifyEmailVerificationToken(mocks.Ctx, testTokenValue)

		// Assert
		assert.NotNil(test, err)
		assert.Nil(test, token)
		assert.Error(test, err)
		assert.IsType(test, &Error{}, err)
		assert.Contains(test, err.Error(), "Invalid token")
	})

	test.Run("VerifyResetPasswordToken_Type_Error", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testToken := model.NewToken(testTokenValue)
		testToken.Type = commonJWT.EmailVerificationTokenType

		mocks.MockTokenRepo.EXPECT().GetByToken(
			gomock.Any(),
			testTokenValue,
		).Return(testToken, nil)

		token, err := mocks.TokenService.VerifyResetPasswordToken(mocks.Ctx, testTokenValue)

		// Assert
		assert.NotNil(test, err)
		assert.Nil(test, token)
		assert.Error(test, err)
		assert.IsType(test, &Error{}, err)
		assert.Contains(test, err.Error(), "Invalid token type")
	})

	// GenerateJWTToken
	test.Run("GenerateJWTToken_Success", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		mocks.MockJWTManager.EXPECT().SignToken(
			testEmail,
			gomock.Any(),
			commonJWT.AccessTokenType,
		).Return(
			&testTokenValue,
			nil,
		)

		response, expiryDate, err := mocks.TokenService.GenerateJWTToken(
			mocks.Ctx,
			testEmail,
			AuthenticationTokenExpiry,
			commonJWT.AccessTokenType,
		)

		// Assert
		assert.NoError(test, err)
		assert.NotNil(test, response)
		assert.NotNil(test, expiryDate)
		assert.Equal(test, testTokenValue, *response)
	})

	test.Run("GenerateJWTToken_Signing_Error", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		mocks.MockJWTManager.EXPECT().SignToken(
			testEmail,
			gomock.Any(),
			commonJWT.AccessTokenType,
		).Return(
			nil,
			errExample,
		)
		mocks.MockLogger.EXPECT().Error(errExample, "Error creating jwt token")

		response, expiryDate, err := mocks.TokenService.GenerateJWTToken(
			mocks.Ctx,
			testEmail,
			AuthenticationTokenExpiry,
			commonJWT.AccessTokenType,
		)

		// Assert
		assert.Error(test, err)
		assert.Nil(test, response)
		assert.Nil(test, expiryDate)
		assert.Equal(test, "Error creating jwt token", err.Error())
	})

	// GenerateJWTTokens
	test.Run("GenerateJWTTokens_Success", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		newRefreshTokenValue := "new-refresh-token"

		mocks.MockJWTManager.EXPECT().SignToken(
			testEmail,
			gomock.Any(),
			commonJWT.AccessTokenType,
		).Return(
			&testTokenValue,
			nil,
		)
		mocks.MockJWTManager.EXPECT().SignToken(
			testEmail,
			gomock.Any(),
			commonJWT.RefreshTokenType,
		).Return(
			&newRefreshTokenValue,
			nil,
		)
		mocks.MockTokenRepo.EXPECT().InsertToken(
			gomock.Any(),
			gomock.Any(),
		).Return(
			primitive.NewObjectID(),
			nil,
		)
		response, err := mocks.TokenService.GenerateJWTTokens(
			mocks.Ctx,
			testUser,
			nil,
		)

		// Assert
		assert.NoError(test, err)
		assert.NotNil(test, response)
		assert.Equal(test, newRefreshTokenValue, response.RefreshToken)
		assert.Equal(test, testTokenValue, response.AuthToken)
	})
	test.Run("GenerateJWTTokens_Success", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		newRefreshTokenValue := "new-refresh-token"

		mocks.MockJWTManager.EXPECT().SignToken(
			testEmail,
			gomock.Any(),
			commonJWT.AccessTokenType,
		).Return(
			&testTokenValue,
			nil,
		)
		mocks.MockJWTManager.EXPECT().SignToken(
			testEmail,
			gomock.Any(),
			commonJWT.RefreshTokenType,
		).Return(
			&newRefreshTokenValue,
			nil,
		)
		mocks.MockTokenRepo.EXPECT().Remove(
			gomock.Any(),
			refreshTokenValue,
		).Return(nil)
		mocks.MockTokenRepo.EXPECT().InsertToken(
			gomock.Any(),
			gomock.Any(),
		).Return(
			primitive.NewObjectID(),
			nil,
		)
		response, err := mocks.TokenService.GenerateJWTTokens(
			mocks.Ctx,
			testUser,
			&refreshTokenValue,
		)

		// Assert
		assert.NoError(test, err)
		assert.NotNil(test, response)
		assert.Equal(test, newRefreshTokenValue, response.RefreshToken)
		assert.Equal(test, testTokenValue, response.AuthToken)
	})

	test.Run("GenerateJWTTokens_InsertToken_Error", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		newRefreshTokenValue := "new-refresh-token"

		mocks.MockJWTManager.EXPECT().SignToken(
			testEmail,
			gomock.Any(),
			commonJWT.AccessTokenType,
		).Return(
			&testTokenValue,
			nil,
		)
		mocks.MockJWTManager.EXPECT().SignToken(
			testEmail,
			gomock.Any(),
			commonJWT.RefreshTokenType,
		).Return(
			&newRefreshTokenValue,
			nil,
		)
		mocks.MockTokenRepo.EXPECT().Remove(
			gomock.Any(),
			refreshTokenValue,
		).Return(nil)
		mocks.MockTokenRepo.EXPECT().InsertToken(
			gomock.Any(),
			gomock.Any(),
		).Return(
			nil,
			errExample,
		)
		response, err := mocks.TokenService.GenerateJWTTokens(
			mocks.Ctx,
			testUser,
			&refreshTokenValue,
		)

		// Assert
		assert.Error(test, err)
		assert.Nil(test, response)
		assert.EqualError(test, err, "Could not insert new refresh token in DB: test-error")
	})

	test.Run("GenerateJWTTokens_Remove_Error", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		newRefreshTokenValue := "new-refresh-token"

		mocks.MockJWTManager.EXPECT().SignToken(
			testEmail,
			gomock.Any(),
			commonJWT.AccessTokenType,
		).Return(
			&testTokenValue,
			nil,
		)
		mocks.MockJWTManager.EXPECT().SignToken(
			testEmail,
			gomock.Any(),
			commonJWT.RefreshTokenType,
		).Return(
			&newRefreshTokenValue,
			nil,
		)
		mocks.MockTokenRepo.EXPECT().Remove(
			gomock.Any(),
			refreshTokenValue,
		).Return(errExample)

		response, err := mocks.TokenService.GenerateJWTTokens(
			mocks.Ctx,
			testUser,
			&refreshTokenValue,
		)

		// Assert
		assert.Error(test, err)
		assert.Nil(test, response)
		assert.EqualError(test, err, "Refresh token is not listed in DB: test-error")
	})

	test.Run("GenerateJWTTokens_RefreshTokenGeneration_Error", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()

		mocks.MockJWTManager.EXPECT().SignToken(
			testEmail,
			gomock.Any(),
			commonJWT.AccessTokenType,
		).Return(
			&testTokenValue,
			nil,
		)
		mocks.MockJWTManager.EXPECT().SignToken(
			testEmail,
			gomock.Any(),
			commonJWT.RefreshTokenType,
		).Return(
			nil,
			errExample,
		)
		mocks.MockLogger.EXPECT().Error(errExample, "Error creating jwt token")

		response, err := mocks.TokenService.GenerateJWTTokens(
			mocks.Ctx,
			testUser,
			&refreshTokenValue,
		)

		// Assert
		assert.Error(test, err)
		assert.Nil(test, response)
		assert.EqualError(test, err, "Error creating refresh token")
	})

	test.Run("GenerateJWTTokens_AccessTokenGeneration_Error", func(test *testing.T) {

		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()

		mocks.MockJWTManager.EXPECT().SignToken(
			testEmail,
			gomock.Any(),
			commonJWT.AccessTokenType,
		).Return(
			nil,
			errExample,
		)
		mocks.MockLogger.EXPECT().Error(errExample, "Error creating jwt token")

		response, err := mocks.TokenService.GenerateJWTTokens(
			mocks.Ctx,
			testUser,
			&refreshTokenValue,
		)

		// Assert
		assert.Error(test, err)
		assert.Nil(test, response)
		assert.EqualError(test, err, "Error creating authentication token")
	})
}

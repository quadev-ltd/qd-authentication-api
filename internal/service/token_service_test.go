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
	commonToken "github.com/quadev-ltd/qd-common/pkg/token"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"

	jwtManagerMock "qd-authentication-api/internal/jwt/mock"
	"qd-authentication-api/internal/model"
	repositoryMock "qd-authentication-api/internal/repository/mock"
	"qd-authentication-api/internal/util"
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
	mockTimeProvider := &util.MockTimeProvider{}
	tokenService := NewTokenService(
		mockTokenRepo,
		mockJWTManager,
		mockTimeProvider,
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
	exampleauthTokenClaims := &commonJWT.TokenClaims{
		Email:  testEmail,
		Type:   commonToken.AuthTokenType,
		Expiry: util.MockedTime.Add(AuthenticationTokenDuration),
		UserID: userID.Hex(),
	}
	exampleRefreshTokenClaims := &commonJWT.TokenClaims{
		Email:  testEmail,
		Type:   commonToken.RefreshTokenType,
		Expiry: util.MockedTime.Add(RefreshTokenDuration),
		UserID: userID.Hex(),
	}
	// VerifyJWTToken
	test.Run("VerifyJWTToken_VerifyToken_Error", func(test *testing.T) {
		// Arrange
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		token := "invalid-token"

		mocks.MockJWTManager.EXPECT().VerifyToken(token).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error verifying token")

		// Act
		email, err := mocks.TokenService.VerifyJWTToken(mocks.Ctx, token)

		// Assert
		assert.Error(test, err)
		assert.Nil(test, email)
		assert.Equal(test, "Invalid or expired token", err.Error())
	})

	test.Run("VerifyJWTToken_GetEmailFromToken_Error", func(test *testing.T) {
		// Arrange
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		token := "valid-token"

		mocks.MockJWTManager.EXPECT().VerifyToken(token).Return(&jwt.Token{}, nil)
		mocks.MockJWTManager.EXPECT().GetClaimsFromToken(gomock.Any()).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error getting claims from token")

		// Act
		email, err := mocks.TokenService.VerifyJWTToken(mocks.Ctx, token)

		// Assert
		assert.Error(test, err)
		assert.Nil(test, email)
		assert.Equal(test, "Error getting claims from token", err.Error())
	})

	test.Run("VerifyJWTToken_Success", func(test *testing.T) {
		// Arrange
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		token := "valid-token"
		jwtToken := jwt.Token{}
		mocks.MockJWTManager.EXPECT().VerifyToken(token).Return(&jwtToken, nil)
		mocks.MockJWTManager.EXPECT().GetClaimsFromToken(&jwtToken).Return(authTokenClaims, nil)

		// Act
		resultClaims, err := mocks.TokenService.VerifyJWTToken(mocks.Ctx, token)

		// Assert
		assert.NoError(test, err)
		assert.NotNil(test, resultClaims)
		assert.Equal(test, authTokenClaims.Email, resultClaims.Email)
		assert.Equal(test, authTokenClaims.Type, resultClaims.Type)
		assert.Equal(test, authTokenClaims.Expiry, resultClaims.Expiry)
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
		mocks.MockLogger.EXPECT().Error(errorExample, "Error verifying token")

		// Test RefreshToken
		user, err := mocks.TokenService.VerifyJWTToken(mocks.Ctx, token)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Invalid or expired token", err.Error())
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
		mocks.MockJWTManager.EXPECT().GetClaimsFromToken(gomock.Any()).Return(nil, errorExample)
		mocks.MockLogger.EXPECT().Error(errorExample, "Error getting claims from token")

		// Test RefreshToken
		user, err := mocks.TokenService.VerifyJWTToken(mocks.Ctx, token)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error getting claims from token", err.Error())
		assert.Nil(test, user)
	})

	test.Run("VerifyJWTToken_Success", func(test *testing.T) {
		// Arrange
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		jwtToken := &jwt.Token{}

		mocks.MockJWTManager.EXPECT().VerifyToken(refreshTokenValue).Return(jwtToken, nil)
		mocks.MockJWTManager.EXPECT().GetClaimsFromToken(jwtToken).Return(authTokenClaims, nil)

		// Test RefreshToken
		resultClaims, resultError := mocks.TokenService.VerifyJWTToken(mocks.Ctx, refreshTokenValue)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, resultClaims)
		assert.Equal(test, authTokenClaims.Email, resultClaims.Email)
		assert.Equal(test, authTokenClaims.Type, resultClaims.Type)
		assert.Equal(test, authTokenClaims.Expiry, resultClaims.Expiry)
	})

	// VerifyResetPasswordToken
	test.Run("VerifyResetPasswordToken_Success", func(test *testing.T) {
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testToken := model.NewToken(verificationTokenHash)
		testToken.Type = commonToken.ResetPasswordTokenType
		testUserID := primitive.NewObjectID()

		mocks.MockTokenRepo.EXPECT().GetByUserIDAndTokenType(
			gomock.Any(),
			testUserID,
			testToken.Type,
		).Return(testToken, nil)

		// Act
		token, err := mocks.TokenService.VerifyResetPasswordToken(
			mocks.Ctx,
			testUserID.Hex(),
			verificationTokenValue,
		)

		// Assert
		assert.NoError(test, err)
		assert.NotNil(test, token)
	})

	test.Run("VerifyResetPasswordToken_Expired_Error", func(test *testing.T) {
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testToken := model.NewToken(verificationTokenHash)
		testToken.Type = commonToken.ResetPasswordTokenType
		testToken.ExpiresAt = util.MockedTime.Add(-1 * time.Second)
		testUserID := primitive.NewObjectID()

		mocks.MockTokenRepo.EXPECT().GetByUserIDAndTokenType(
			gomock.Any(),
			testUserID,
			testToken.Type,
		).Return(testToken, nil)

		// Act
		token, err := mocks.TokenService.VerifyResetPasswordToken(
			mocks.Ctx,
			testUserID.Hex(),
			verificationTokenValue,
		)

		// Assert
		assert.Nil(test, token)
		assert.Error(test, err)
		assert.Equal(test, "token_expired", err.Error())
	})

	test.Run("VerifyResetPasswordToken_MissingToken_Error", func(test *testing.T) {
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testTokenValue := "test-token"
		exampleError := errors.New("test-error")
		testUserID := primitive.NewObjectID()

		mocks.MockTokenRepo.EXPECT().GetByUserIDAndTokenType(
			gomock.Any(),
			testUserID,
			commonToken.ResetPasswordTokenType,
		).Return(nil, exampleError)
		mocks.MockLogger.EXPECT().Error(exampleError, "Error getting token by user id and type")
		// Act
		token, err := mocks.TokenService.VerifyResetPasswordToken(
			mocks.Ctx,
			testUserID.Hex(),
			testTokenValue,
		)

		// Assert
		assert.Nil(test, token)
		assert.Error(test, err)
		assert.Equal(test, "invalid_token", err.Error())
	})

	// GenerateEmailVerificationToken
	test.Run("GenerateEmailVerificationToken_Success", func(test *testing.T) {
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		mocks.MockTokenRepo.EXPECT().InsertToken(
			gomock.Any(),
			gomock.Any(),
		).Return(primitive.NewObjectID(), nil)
		mocks.MockTokenRepo.EXPECT().
			RemoveAllByUserIDAndTokenType(gomock.Any(), userID, commonToken.EmailVerificationTokenType).
			Return(nil)

		token, resultError := mocks.TokenService.GenerateEmailVerificationToken(mocks.Ctx, userID)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, token)
	})

	test.Run("GenerateEmailVerificationToken_Insert_Error", func(test *testing.T) {
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		mocks.MockTokenRepo.EXPECT().
			RemoveAllByUserIDAndTokenType(gomock.Any(), userID, commonToken.EmailVerificationTokenType).
			Return(nil)
		mocks.MockTokenRepo.EXPECT().InsertToken(
			gomock.Any(),
			gomock.Any(),
		).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error inserting verification token in DB")

		token, resultError := mocks.TokenService.GenerateEmailVerificationToken(mocks.Ctx, userID)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, token)
		assert.EqualError(test, resultError, "Error storing verification token")
	})

	test.Run("GenerateEmailVerificationToken_RemoveOldToken_Error", func(test *testing.T) {
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		mocks.MockTokenRepo.EXPECT().
			RemoveAllByUserIDAndTokenType(gomock.Any(), userID, commonToken.EmailVerificationTokenType).
			Return(errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error removing old tokens")

		token, resultError := mocks.TokenService.GenerateEmailVerificationToken(mocks.Ctx, userID)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, token)
		assert.EqualError(test, resultError, "Could not remove old tokens")
	})

	// GeneratePasswordResetToken
	test.Run("GeneratePasswordResetToken_Success", func(test *testing.T) {
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		mocks.MockTokenRepo.EXPECT().InsertToken(
			gomock.Any(),
			gomock.Any(),
		).Return(primitive.NewObjectID(), nil)
		mocks.MockTokenRepo.EXPECT().
			RemoveAllByUserIDAndTokenType(gomock.Any(), userID, commonToken.ResetPasswordTokenType).
			Return(nil)

		token, resultError := mocks.TokenService.GeneratePasswordResetToken(mocks.Ctx, userID)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, token)
	})

	test.Run("GeneratePasswordResetToken_Insert_Error", func(test *testing.T) {
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		mocks.MockTokenRepo.EXPECT().
			RemoveAllByUserIDAndTokenType(gomock.Any(), userID, commonToken.ResetPasswordTokenType).
			Return(nil)
		mocks.MockTokenRepo.EXPECT().InsertToken(
			gomock.Any(),
			gomock.Any(),
		).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error inserting verification token in DB")

		token, resultError := mocks.TokenService.GeneratePasswordResetToken(mocks.Ctx, userID)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, token)
	})

	test.Run("GeneratePasswordResetToken_RemoveOldTokens_Error", func(test *testing.T) {
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		mocks.MockTokenRepo.EXPECT().
			RemoveAllByUserIDAndTokenType(gomock.Any(), userID, commonToken.ResetPasswordTokenType).
			Return(errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error removing old tokens")

		token, resultError := mocks.TokenService.GeneratePasswordResetToken(mocks.Ctx, userID)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, token)
	})

	// VerifyEmailVerificationToken
	test.Run("VerifyEmailVerificationToken_Expired_Error", func(test *testing.T) {
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testToken := model.NewToken(testTokenHashValue)
		testToken.ExpiresAt = util.MockedTime.Add(1 * time.Second)
		testToken.TokenHash = verificationTokenHash

		mocks.MockTokenRepo.EXPECT().GetByUserIDAndTokenType(
			gomock.Any(),
			testToken.UserID,
			testToken.Type,
		).Return(testToken, nil)

		resultToken, err := mocks.TokenService.VerifyEmailVerificationToken(mocks.Ctx, testToken.UserID.Hex(), verificationTokenValue)

		// Assert
		assert.NotNil(test, resultToken)
		assert.NoError(test, err)
		assert.Equal(test, testToken.TokenHash, resultToken.TokenHash)
		assert.Equal(test, testToken.Type, resultToken.Type)
		assert.Equal(test, testToken.Revoked, resultToken.Revoked)
	})
	test.Run("VerifyEmailVerificationToken_Expired_Error", func(test *testing.T) {
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		expiredToken := model.NewToken(testTokenHashValue)
		expiredToken.ExpiresAt = util.MockedTime.Add(-1 * time.Second)
		expiredToken.TokenHash = verificationTokenHash

		mocks.MockTokenRepo.EXPECT().GetByUserIDAndTokenType(
			gomock.Any(),
			expiredToken.UserID,
			expiredToken.Type,
		).Return(expiredToken, nil)

		token, err := mocks.TokenService.VerifyEmailVerificationToken(mocks.Ctx, expiredToken.UserID.Hex(), verificationTokenValue)

		// Assert
		assert.NotNil(test, err)
		assert.Nil(test, token)
		assert.Error(test, err)
		assert.IsType(test, &Error{}, err)
		assert.Contains(test, err.Error(), "token_expired")
	})

	test.Run("VerifyEmailVerificationToken_WrongUserID_Error", func(test *testing.T) {
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testToken := model.NewToken(testTokenHashValue)
		testToken.Type = commonToken.ResetPasswordTokenType

		mocks.MockLogger.EXPECT().Error(gomock.Any(), "Error converting user id to object id")

		token, err := mocks.TokenService.VerifyEmailVerificationToken(mocks.Ctx, "wrong-id", testTokenValue)

		// Assert
		assert.NotNil(test, err)
		assert.Nil(test, token)
		assert.Error(test, err)
		assert.IsType(test, &Error{}, err)
		assert.EqualError(test, err, "invalid_user_id")
	})

	test.Run("VerifyEmailVerificationToken_Value_Error", func(test *testing.T) {
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testToken := model.NewToken(testTokenHashValue)
		testToken.Type = commonToken.ResetPasswordTokenType

		mocks.MockTokenRepo.EXPECT().GetByUserIDAndTokenType(
			gomock.Any(),
			testToken.UserID,
			commonToken.EmailVerificationTokenType,
		).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error getting token by user id and type")

		token, err := mocks.TokenService.VerifyEmailVerificationToken(mocks.Ctx, testToken.UserID.Hex(), testTokenValue)

		// Assert
		assert.NotNil(test, err)
		assert.Nil(test, token)
		assert.Error(test, err)
		assert.IsType(test, &Error{}, err)
		assert.Contains(test, err.Error(), "invalid_token")
	})

	// GenerateJWTToken
	test.Run("GenerateJWTToken_Success", func(test *testing.T) {
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		mocks.MockJWTManager.EXPECT().SignToken(
			gomock.Eq(exampleauthTokenClaims),
		).Return(
			&testTokenHashValue,
			nil,
		)

		response, err := mocks.TokenService.GenerateJWTToken(
			mocks.Ctx,
			exampleauthTokenClaims,
		)

		// Assert
		assert.NoError(test, err)
		assert.NotNil(test, response)
		assert.Equal(test, testTokenHashValue, *response)
	})

	test.Run("GenerateJWTToken_Signing_Error", func(test *testing.T) {
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()
		mocks.MockJWTManager.EXPECT().SignToken(
			gomock.Eq(exampleauthTokenClaims),
		).Return(
			nil,
			errExample,
		)
		mocks.MockLogger.EXPECT().Error(errExample, "Error creating jwt token")

		response, err := mocks.TokenService.GenerateJWTToken(
			mocks.Ctx,
			exampleauthTokenClaims,
		)

		// Assert
		assert.Error(test, err)
		assert.Nil(test, response)
		assert.Equal(test, "Error creating jwt token", err.Error())
	})

	// GenerateJWTTokens
	test.Run("GenerateJWTTokens_Success", func(test *testing.T) {
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		userID, err := primitive.ObjectIDFromHex(exampleauthTokenClaims.UserID)
		if err != nil {
			test.Fatal(err)
		}
		testUser.ID = userID

		mocks.MockJWTManager.EXPECT().SignToken(
			gomock.Eq(exampleauthTokenClaims),
		).Return(
			&testTokenHashValue,
			nil,
		)
		mocks.MockJWTManager.EXPECT().SignToken(
			gomock.Eq(exampleRefreshTokenClaims),
		).Return(
			&newRefreshTokenValue,
			nil,
		)
		response, err := mocks.TokenService.GenerateJWTTokens(
			mocks.Ctx,
			testUser.Email,
			testUser.ID.Hex(),
		)

		// Assert
		assert.NoError(test, err)
		assert.NotNil(test, response)
		assert.Equal(test, newRefreshTokenValue, response.RefreshToken)
		assert.Equal(test, testTokenHashValue, response.AuthToken)
	})

	test.Run("GenerateJWTTokens_RefreshTokenGeneration_Error", func(test *testing.T) {
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		userID, err := primitive.ObjectIDFromHex(exampleauthTokenClaims.UserID)
		if err != nil {
			test.Fatal(err)
		}
		testUser.ID = userID

		mocks.MockJWTManager.EXPECT().SignToken(
			gomock.Eq(exampleauthTokenClaims),
		).Return(
			&testTokenHashValue,
			nil,
		)
		mocks.MockJWTManager.EXPECT().SignToken(
			gomock.Eq(exampleRefreshTokenClaims),
		).Return(
			nil,
			errExample,
		)
		mocks.MockLogger.EXPECT().Error(errExample, "Error creating jwt token")

		response, err := mocks.TokenService.GenerateJWTTokens(
			mocks.Ctx,
			testUser.Email,
			testUser.ID.Hex(),
		)

		// Assert
		assert.Error(test, err)
		assert.Nil(test, response)
		assert.EqualError(test, err, "Error creating refresh token: Error creating jwt token")
	})

	test.Run("GenerateJWTTokens_AuthTokenGeneration_Error", func(test *testing.T) {
		mocks := createTokenService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		userID, err := primitive.ObjectIDFromHex(exampleauthTokenClaims.UserID)
		if err != nil {
			test.Fatal(err)
		}
		testUser.ID = userID

		mocks.MockJWTManager.EXPECT().SignToken(
			gomock.Eq(exampleauthTokenClaims),
		).Return(
			nil,
			errExample,
		)
		mocks.MockLogger.EXPECT().Error(errExample, "Error creating jwt token")

		response, err := mocks.TokenService.GenerateJWTTokens(
			mocks.Ctx,
			testUser.Email,
			testUser.ID.Hex(),
		)

		// Assert
		assert.Error(test, err)
		assert.Nil(test, response)
		assert.EqualError(test, err, "Error creating authentication token: Error creating jwt token")
	})
}

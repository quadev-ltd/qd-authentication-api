package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang/mock/gomock"
	commonJWT "github.com/quadev-ltd/qd-common/pkg/jwt"
	"github.com/quadev-ltd/qd-common/pkg/log"
	loggerMock "github.com/quadev-ltd/qd-common/pkg/log/mock"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"

	jwtPkg "qd-authentication-api/internal/jwt"
	"qd-authentication-api/internal/model"
	repositoryMock "qd-authentication-api/internal/repository/mock"
	serviceMock "qd-authentication-api/internal/service/mock"
)

const (
	testEmail            = "test@example.com"
	testPassword         = "Password123!"
	testFirstName        = "John"
	testLastName         = "Doe"
	invalidEmail         = "invalid-email"
	newRefreshTokenValue = "test_token_example"
)

var (
	testDateOfBirth   = time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	userID            = primitive.NewObjectID()
	errExample        = errors.New("test-error")
	refreshTokenValue = "refresh-token"
	testTokenValue    = "test-token"
	accessTokenClaims = &jwtPkg.TokenClaims{
		Email:  testEmail,
		Type:   string(commonJWT.AccessTokenType),
		Expiry: time.Now().Add(5 * time.Minute),
	}
	refreshTokenClaims = &jwtPkg.TokenClaims{
		Email:  accessTokenClaims.Email,
		Type:   string(commonJWT.RefreshTokenType),
		Expiry: accessTokenClaims.Expiry,
	}
)

type AuthServiceMockedParams struct {
	MockUserRepo          repositoryMock.MockUserRepositoryer
	MockEmailService      serviceMock.MockEmailServicer
	MockTokenService      serviceMock.MockTokenServicer
	MockLogger            *loggerMock.MockLoggerer
	AuthenticationService UserServicer
	Controller            *gomock.Controller
	Ctx                   context.Context
}

// TODO: return an object
func createUserService(test *testing.T) *AuthServiceMockedParams {
	controller := gomock.NewController(test)
	mockUserRepo := repositoryMock.NewMockUserRepositoryer(controller)
	mockEmailService := serviceMock.NewMockEmailServicer(controller)
	mockTokenService := serviceMock.NewMockTokenServicer(controller)
	mockLogger := loggerMock.NewMockLoggerer(controller)
	userService := NewUserService(
		mockEmailService,
		mockTokenService,
		mockUserRepo,
	)
	ctx := context.WithValue(context.Background(), log.LoggerKey, mockLogger)

	return &AuthServiceMockedParams{
		*mockUserRepo,
		*mockEmailService,
		*mockTokenService,
		mockLogger,
		userService,
		controller,
		ctx,
	}
}

func TestAuthenticationService(test *testing.T) {
	// Register
	test.Run("Register_Success", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(false, nil)
		mocks.MockUserRepo.EXPECT().InsertUser(gomock.Any(), gomock.Any()).Return(userID, nil)
		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(gomock.Any(), userID).Return(&testTokenValue, nil)
		mocks.MockEmailService.EXPECT().SendVerificationMail(gomock.Any(), testEmail, testFirstName, gomock.Any()).Return(nil)

		err := mocks.AuthenticationService.Register(
			mocks.Ctx,
			testEmail,
			testPassword,
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)
		assert.NoError(test, err)
	})
	test.Run("Register_Email_Uniqueness", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(true, nil)

		err := mocks.AuthenticationService.Register(
			mocks.Ctx,
			testEmail,
			testPassword,
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)

		assert.Error(test, err)
		assert.Equal(test, (&model.EmailInUseError{Email: testEmail}).Error(), err.Error())
	})
	test.Run("Register_ExistsFail_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), invalidEmail).Return(false, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, fmt.Sprintf("Error checking user existence by email: %v", invalidEmail))

		err := mocks.AuthenticationService.Register(
			mocks.Ctx,
			invalidEmail,
			testPassword,
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)

		assert.Error(test, err)
		assert.Equal(test, fmt.Sprintf("Error checking user existence by email: %v", invalidEmail), err.Error())
	})
	test.Run("Register_Invalid_Email", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), invalidEmail).Return(false, nil)

		err := mocks.AuthenticationService.Register(
			mocks.Ctx,
			invalidEmail,
			testPassword,
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)

		assert.Error(test, err)
		var validationErrs validator.ValidationErrors
		assert.ErrorAs(test, err, &validationErrs)
		assert.Contains(test, err.Error(), "Email")
	})
	test.Run("Register_Invalid_DOB", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()
		invalidDateOfBirth := time.Time{}

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(false, nil)

		err := mocks.AuthenticationService.Register(
			mocks.Ctx,
			testEmail,
			testPassword,
			testFirstName,
			testLastName,
			&invalidDateOfBirth,
		)

		assert.Error(test, err)
		var validationErrs validator.ValidationErrors
		assert.ErrorAs(test, err, &validationErrs)
		assert.Contains(test, err.Error(), "DateOfBirth")
	})
	test.Run("Register_Password_Error", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(false, nil)

		error := mocks.AuthenticationService.Register(
			mocks.Ctx,
			testEmail,
			"testPassword",
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)
		assert.Error(test, error)
		assert.IsType(test, &NoComplexPasswordError{}, error)
		assert.Equal(test, "Password does not meet complexity requirements", error.Error())
	})

	test.Run("Register_Fail_Parsing_Inserted_ID_error", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(false, nil)
		mocks.MockUserRepo.EXPECT().InsertUser(gomock.Any(), gomock.Any()).Return("", nil)

		err := mocks.AuthenticationService.Register(
			mocks.Ctx,
			testEmail,
			testPassword,
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)
		assert.Error(test, err)
		assert.Equal(test, "InsertedID is not of type primitive.ObjectID", err.Error())
	})

	test.Run("Register_Send_email_error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(false, nil)
		mocks.MockUserRepo.EXPECT().InsertUser(gomock.Any(), gomock.Any()).Return(userID, nil)
		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(gomock.Any(), userID).Return(&testTokenValue, nil)
		mocks.MockEmailService.EXPECT().SendVerificationMail(
			gomock.Any(),
			testEmail,
			testFirstName,
			gomock.Any(),
		).Return(errExample)

		error := mocks.AuthenticationService.Register(
			mocks.Ctx,
			testEmail,
			testPassword,
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)
		assert.Error(test, error)
		assert.IsType(test, &SendEmailError{}, error)
		assert.Equal(test, "Error sending verification email", error.Error())
	})

	// 	// Verify
	test.Run("VerifyEmail_Verify_Success", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		testToken := model.NewToken(newRefreshTokenValue)

		mocks.MockTokenService.EXPECT().VerifyEmailVerificationToken(gomock.Any(), testToken.Token).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)
		mocks.MockUserRepo.EXPECT().UpdateStatus(gomock.Any(), testUser).Return(nil)
		mocks.MockTokenService.EXPECT().RemoveUsedToken(gomock.Any(), testToken.Token).Return(nil)

		// Test successful verification
		err := mocks.AuthenticationService.VerifyEmail(mocks.Ctx, testToken.Token)

		assert.NoError(test, err)
		assert.Equal(test, model.AccountStatusVerified, testUser.AccountStatus)
	})

	test.Run("VerifyEmail_Returns_error", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testToken := model.NewToken(newRefreshTokenValue)

		mocks.MockTokenService.EXPECT().VerifyEmailVerificationToken(gomock.Any(), testToken.Token).Return(nil, errExample)

		// Test Verify
		resultError := mocks.AuthenticationService.VerifyEmail(mocks.Ctx, testToken.Token)

		assert.Error(test, resultError)
		assert.Equal(test, "test-error", resultError.Error())
	})

	test.Run("VerifyEmail_Get_User_By_ID_Error", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testToken := model.NewToken(newRefreshTokenValue)

		mocks.MockTokenService.EXPECT().VerifyEmailVerificationToken(gomock.Any(), testToken.Token).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error getting user by ID")

		// Test Verify
		resultError := mocks.AuthenticationService.VerifyEmail(mocks.Ctx, testToken.Token)

		assert.Error(test, resultError)
		assert.NotNil(test, resultError)
		assert.Equal(test, "Invalid verification token", resultError.Error())
	})
	test.Run("Invalid verification token", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testToken := model.NewToken(newRefreshTokenValue)
		testUser := model.NewUser()
		testUser.AccountStatus = model.AccountStatusVerified

		mocks.MockTokenService.EXPECT().VerifyEmailVerificationToken(gomock.Any(), testToken.Token).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)

		// Test Verify
		resultError := mocks.AuthenticationService.VerifyEmail(mocks.Ctx, testToken.Token)

		assert.Error(test, resultError)
		assert.IsType(test, &Error{}, resultError)
		assert.Equal(test, "Email already verified", resultError.Error())
	})
	test.Run("VerifyEmail_Update_error", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testToken := model.NewToken(newRefreshTokenValue)
		testUser := model.NewUser()

		mocks.MockTokenService.EXPECT().VerifyEmailVerificationToken(gomock.Any(), testToken.Token).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)
		mocks.MockUserRepo.EXPECT().UpdateStatus(gomock.Any(), testUser).Return(errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error updating user status")
		// Act
		resultError := mocks.AuthenticationService.VerifyEmail(mocks.Ctx, testToken.Token)

		// Assert
		assert.Error(test, resultError)
		assert.Equal(test, "Error updating user status", resultError.Error())
	})

	test.Run("VerifyEmail_RemoveToken_error", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testToken := model.NewToken(newRefreshTokenValue)
		testUser := model.NewUser()

		mocks.MockTokenService.EXPECT().VerifyEmailVerificationToken(gomock.Any(), testToken.Token).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)
		mocks.MockUserRepo.EXPECT().UpdateStatus(gomock.Any(), testUser).Return(nil)
		mocks.MockTokenService.EXPECT().RemoveUsedToken(gomock.Any(), testToken.Token).Return(errExample)

		// Act
		resultError := mocks.AuthenticationService.VerifyEmail(mocks.Ctx, testToken.Token)

		// Assert
		assert.Error(test, resultError)
		assert.Equal(test, "test-error", resultError.Error())
	})

	// Authenticate
	test.Run("Authenticate_GetByEmail_error", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		errorMessage := "Database error"
		errorExample := errors.New(errorMessage)

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, errorExample)
		mocks.MockLogger.EXPECT().Error(errorExample, fmt.Sprintf("Error getting user by email: %v", testEmail))

		// Test Authenticate
		user, err := mocks.AuthenticationService.Authenticate(mocks.Ctx, testEmail, "password")

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error getting user by email", err.Error())
		assert.Nil(test, user)
	})
	test.Run("Authenticate_User_Not_Found", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		email := "test@example.com"
		password := "password"

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), email).Return(nil, nil)

		// Test Authenticate
		user, err := mocks.AuthenticationService.Authenticate(mocks.Ctx, email, password)

		assert.Error(test, err)
		assert.Equal(test, "Wrong Email", err.Error())
		assert.Nil(test, user)
	})
	test.Run("Authenticate_Invalid_Password", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		email := "test@example.com"

		user := model.NewUser()
		invalidPassword := "invalidpassword"

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), email).Return(user, nil)

		// Test Authenticate
		resultUser, resultError := mocks.AuthenticationService.Authenticate(mocks.Ctx, email, invalidPassword)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, resultUser)
		assert.Equal(test, "Wrong Password", resultError.Error())
	})
	test.Run("Authenticate_AuthToken_Signing_Error", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		user := model.NewUser()
		user.PasswordHash = "$2a$10$b4R.rxNHsELRW/JaqI1kS.CXO.xVamz.rwFXxchWD2pdKhKzZp94u"
		user.PasswordSalt = "7jQQnlalvK1E0iDzugF18ewa1Auf7R71Dr6OWnJbZbI="

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(user, nil)
		mocks.MockTokenService.EXPECT().GenerateJWTTokens(gomock.Any(), user, nil).Return(nil, errExample)

		// Test Authenticate
		resultUser, resultError := mocks.AuthenticationService.Authenticate(
			mocks.Ctx,
			testEmail,
			testPassword,
		)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, resultUser)
		assert.Equal(test, "test-error", resultError.Error())
	})

	test.Run("Authenticate_Authenticate_Success", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		user := model.NewUser()
		user.PasswordHash = "$2a$10$b4R.rxNHsELRW/JaqI1kS.CXO.xVamz.rwFXxchWD2pdKhKzZp94u"
		user.PasswordSalt = "7jQQnlalvK1E0iDzugF18ewa1Auf7R71Dr6OWnJbZbI="
		tokenResponse := &model.AuthTokensResponse{
			AuthToken:    "test",
			RefreshToken: "test",
		}

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(user, nil)
		mocks.MockTokenService.EXPECT().GenerateJWTTokens(gomock.Any(), user, nil).Return(tokenResponse, nil)

		// Act
		tokens, resultError := mocks.AuthenticationService.Authenticate(mocks.Ctx, testEmail, testPassword)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, tokens)
		assert.Equal(test, "test", tokens.AuthToken)
		assert.Equal(test, "test", tokens.RefreshToken)
	})

	// // ResendEmailVerification
	test.Run("ResendEmailVerification_GetByEmail_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		errExample := errors.New("User repository error")

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, fmt.Sprintf("Error getting user by email: %v", testEmail))

		// Act
		err := mocks.AuthenticationService.ResendEmailVerification(mocks.Ctx, testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error searching user by email", err.Error())
	})

	test.Run("ResendEmailVerification_GetByEmail_NotFound", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, nil)

		// Act
		err := mocks.AuthenticationService.ResendEmailVerification(mocks.Ctx, testEmail)

		// Assert
		assert.Error(test, err)
		assert.IsType(test, &Error{}, err)
		assert.Contains(test, err.Error(), "Invalid email")
	})

	test.Run("ResendEmailVerification_GetByEmail_AlreadyVerified", func(test *testing.T) {
		// Arrange

		user := model.NewUser()
		user.AccountStatus = model.AccountStatusVerified

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(user, nil)

		// Act
		err := mocks.AuthenticationService.ResendEmailVerification(mocks.Ctx, testEmail)

		// Assert
		assert.Error(test, err)
		assert.IsType(test, &Error{}, err)
		assert.Contains(test, err.Error(), "Email already verified")
	})

	test.Run("ResendEmailVerification_UserUpdate_Error", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)
		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(gomock.Any(), testUser.ID).Return(nil, errExample)

		// Act
		err := mocks.AuthenticationService.ResendEmailVerification(mocks.Ctx, testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "test-error", err.Error())
	})

	test.Run("ResendEmailVerification_SendEmail_Error", func(test *testing.T) {

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		errExample := errors.New("Email service error")

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)
		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(gomock.Any(), testUser.ID).Return(&testTokenValue, nil)
		mocks.MockEmailService.EXPECT().SendVerificationMail(
			mocks.Ctx,
			testEmail,
			testUser.FirstName,
			testTokenValue,
		).Return(errExample)

		// Act
		err := mocks.AuthenticationService.ResendEmailVerification(mocks.Ctx, testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error sending verification email: Email service error", err.Error())
	})

	test.Run("ResendEmailVerification_Success", func(test *testing.T) {

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)
		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(gomock.Any(), testUser.ID).Return(&testTokenValue, nil)
		mocks.MockEmailService.EXPECT().SendVerificationMail(
			mocks.Ctx,
			testEmail,
			testUser.FirstName,
			testTokenValue,
		).Return(nil)

		// Act
		err := mocks.AuthenticationService.ResendEmailVerification(mocks.Ctx, testEmail)

		// Assert
		assert.NoError(test, err)
	})

	// RefreshToken
	test.Run("RefreshToken_VerifyToken_error", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		token := "test-token"
		errorMessage := "Database error"
		errorExample := errors.New(errorMessage)

		mocks.MockTokenService.EXPECT().VerifyJWTToken(gomock.Any(), token).Return(nil, errorExample)

		// Test RefreshToken
		user, err := mocks.AuthenticationService.RefreshToken(mocks.Ctx, token)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, errorExample.Error(), err.Error())
		assert.Nil(test, user)
	})

	test.Run("RefreshToken_User_Not_Found", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		mocks.MockTokenService.EXPECT().VerifyJWTToken(
			gomock.Any(),
			testTokenValue,
		).Return(refreshTokenClaims, nil)
		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error getting user by email claim")

		// Test RefreshToken
		user, err := mocks.AuthenticationService.RefreshToken(mocks.Ctx, testTokenValue)

		assert.Error(test, err)
		assert.Equal(test, "Invalid token", err.Error())
		assert.Nil(test, user)
	})

	test.Run("RefreshToken_InvalidType_Error", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		mocks.MockTokenService.EXPECT().VerifyJWTToken(gomock.Any(), refreshTokenValue).Return(accessTokenClaims, nil)

		// Test RefreshToken
		resultUser, resultError := mocks.AuthenticationService.RefreshToken(mocks.Ctx, refreshTokenValue)

		// Assert
		assert.Error(test, resultError)
		assert.EqualError(test, resultError, "Invalid token type")
		assert.Nil(test, resultUser)
	})

	test.Run("RefreshToken_Success", func(test *testing.T) {
		// Arrange

		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		user := model.NewUser()
		tokenResponse := &model.AuthTokensResponse{
			AuthToken:    "test",
			RefreshToken: "test",
		}

		mocks.MockTokenService.EXPECT().VerifyJWTToken(gomock.Any(), refreshTokenValue).Return(refreshTokenClaims, nil)
		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(user, nil)
		mocks.MockTokenService.EXPECT().GenerateJWTTokens(gomock.Any(), user, &refreshTokenValue).Return(tokenResponse, nil)

		// Test RefreshToken
		resultUser, resultError := mocks.AuthenticationService.RefreshToken(mocks.Ctx, refreshTokenValue)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, resultUser)
		assert.Equal(test, testEmail, user.Email)
	})
}

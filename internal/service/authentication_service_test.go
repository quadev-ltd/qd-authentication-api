package service

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
	"go.mongodb.org/mongo-driver/bson/primitive"

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
	refreshTokenValue = "refreshToken"
	testTokenValue    = "test-token"
)

type AuthServiceMockedParams struct {
	MockUserRepo          repositoryMock.MockUserRepositoryer
	MockEmailService      serviceMock.MockEmailServicer
	MockTokenService      serviceMock.MockTokenServicer
	AuthenticationService AuthenticationServicer
}

// TODO: return an object
func createAuthenticationService(controller *gomock.Controller) *AuthServiceMockedParams {
	mockUserRepo := repositoryMock.NewMockUserRepositoryer(controller)
	mockEmailService := serviceMock.NewMockEmailServicer(controller)
	mockTokenService := serviceMock.NewMockTokenServicer(controller)
	authenticationService := NewAuthenticationService(
		mockEmailService,
		mockTokenService,
		mockUserRepo,
	)

	return &AuthServiceMockedParams{
		*mockUserRepo,
		*mockEmailService,
		*mockTokenService,
		authenticationService,
	}
}

func TestAuthenticationService(test *testing.T) {
	// Register
	test.Run("Register_Success", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()
		mocks := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(false, nil)
		mocks.MockUserRepo.EXPECT().InsertUser(gomock.Any(), gomock.Any()).Return(userID, nil)
		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(gomock.Any(), userID).Return(&testTokenValue, nil)
		mocks.MockEmailService.EXPECT().SendVerificationMail(gomock.Any(), testEmail, testFirstName, gomock.Any()).Return(nil)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		err := mocks.AuthenticationService.Register(
			ctx,
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
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(true, nil)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)
		err := mocks.AuthenticationService.Register(
			ctx,
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
		controller := gomock.NewController(test)
		defer controller.Finish()
		mocks := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), invalidEmail).Return(false, errExample)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)
		err := mocks.AuthenticationService.Register(
			ctx,
			invalidEmail,
			testPassword,
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)

		assert.Error(test, err)
		assert.Equal(test, "Error checking user existence by email: test-error", err.Error())
	})
	test.Run("Register_Invalid_Email", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()
		mocks := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), invalidEmail).Return(false, nil)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)
		err := mocks.AuthenticationService.Register(
			ctx,
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
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)
		invalidDateOfBirth := time.Time{}
		logMock := loggerMock.NewMockLoggerer(controller)

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(false, nil)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)
		err := mocks.AuthenticationService.Register(
			ctx,
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
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(false, nil)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		error := mocks.AuthenticationService.Register(
			ctx,
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
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(false, nil)
		mocks.MockUserRepo.EXPECT().InsertUser(gomock.Any(), gomock.Any()).Return(nil, nil)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		err := mocks.AuthenticationService.Register(
			ctx,
			testEmail,
			testPassword,
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)
		assert.Error(test, err)
		assert.Equal(test, "InsertedID is not of type primitive.ObjectID: <nil>", err.Error())
	})

	// 	test.Run("Register_Inserting_Verifiction_Token", func(test *testing.T) {
	// 		// Arrange
	// 		controller := gomock.NewController(test)
	// 		defer controller.Finish()
	// 		errExample := errors.New("Test error")

	// 		mockUserRepo,
	// 			mockTokenRepository,
	// 			_,
	// 			_,
	// 			authenticationService := createAuthenticationService(controller)
	// 		logMock := loggerMock.NewMockLoggerer(controller)

	// 		mockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(false, nil)
	// 		mockUserRepo.EXPECT().InsertUser(gomock.Any(), gomock.Any()).Return(primitive.NewObjectID(), nil)
	// 		mockTokenRepository.EXPECT().InsertToken(gomock.Any(), gomock.Any()).Return(nil, errExample)

	// 		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)
	//
	// 		error := authenticationService.Register(
	// 			ctx,
	// 			testEmail,
	// 			testPassword,
	// 			testFirstName,
	// 			testLastName,
	// 			&testDateOfBirth,
	// 		)
	// 		assert.Error(test, error)
	// 		assert.Equal(test, "Error inserting verification token in DB: Test error", error.Error())
	// 	})
	test.Run("Register_Send_email_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()
		errExample := errors.New("Test error")

		mocks := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(false, nil)
		mocks.MockUserRepo.EXPECT().InsertUser(gomock.Any(), gomock.Any()).Return(userID, nil)
		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(gomock.Any(), userID).Return(&testTokenValue, nil)
		mocks.MockEmailService.EXPECT().SendVerificationMail(
			gomock.Any(),
			testEmail,
			testFirstName,
			gomock.Any(),
		).Return(errExample)
		logMock.EXPECT().Error(errExample, "Error sending verification email")

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		error := mocks.AuthenticationService.Register(
			ctx,
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
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)

		testUser := model.NewUser()
		testToken := model.NewToken(newRefreshTokenValue)

		mocks.MockTokenService.EXPECT().VerifyEmailVerificationToken(gomock.Any(), testToken.Token).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)
		mocks.MockUserRepo.EXPECT().UpdateStatus(gomock.Any(), testUser).Return(nil)
		mocks.MockTokenService.EXPECT().RemoveUsedToken(gomock.Any(), testToken.Token).Return(nil)

		// Test successful verification
		err := mocks.AuthenticationService.VerifyEmail(context.Background(), testToken.Token)

		assert.NoError(test, err)
		assert.Equal(test, model.AccountStatusVerified, testUser.AccountStatus)
	})
	// 	test.Run("VerifyEmail_Token_expired_error", func(test *testing.T) {
	// 		controller := gomock.NewController(test)
	// 		defer controller.Finish()

	// 		_,
	// 			mockTokenRepo,
	// 			_,
	// 			_,
	// 			authenticationService := createAuthenticationService(controller)

	// 		expiredToken := model.NewToken(newRefreshTokenValue)
	// 		expiredToken.ExpiresAt = time.Now().Add(-1 * time.Second)

	// 		mockTokenRepo.EXPECT().GetByToken(gomock.Any(), expiredToken.Token).Return(expiredToken, nil)

	// 		err := authenticationService.VerifyEmail(context.Background(), expiredToken.Token)

	// 		assert.NotNil(test, err)
	// 		assert.Error(test, err)
	// 		assert.IsType(test, &Error{}, err)
	// 		assert.Contains(test, err.Error(), "Verification token expired")

	// 	})
	test.Run("VerifyEmail_Returns_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)

		testToken := model.NewToken(newRefreshTokenValue)

		mocks.MockTokenService.EXPECT().VerifyEmailVerificationToken(gomock.Any(), testToken.Token).Return(nil, errExample)

		// Test Verify
		resultError := mocks.AuthenticationService.VerifyEmail(context.Background(), testToken.Token)

		assert.Error(test, resultError)
		assert.Equal(test, "test-error", resultError.Error())
	})
	// 	test.Run("VerifyEmail_Token_Wrong_Type_Of_Token_Error", func(test *testing.T) {
	// 		// Arrange
	// 		controller := gomock.NewController(test)
	// 		defer controller.Finish()

	// 		_,
	// 			mockTokenRepo,
	// 			_,
	// 			_,
	// 			authenticationService := createAuthenticationService(controller)

	// 		testToken := model.NewToken(newRefreshTokenValue)
	// 		testToken.Type = commonJWT.RefreshTokenType

	// 		mockTokenRepo.EXPECT().GetByToken(gomock.Any(), testToken.Token).Return(testToken, nil)

	// 		// Test Verify
	// 		resultError := authenticationService.VerifyEmail(context.Background(), testToken.Token)

	// 		assert.Error(test, resultError)
	// 		assert.NotNil(test, resultError)
	// 		assert.Equal(test, "Wrong type of token", resultError.Error())
	// 	})
	test.Run("VerifyEmail_Get_User_By_ID_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)

		testToken := model.NewToken(newRefreshTokenValue)

		mocks.MockTokenService.EXPECT().VerifyEmailVerificationToken(gomock.Any(), testToken.Token).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(nil, errExample)

		// Test Verify
		resultError := mocks.AuthenticationService.VerifyEmail(context.Background(), testToken.Token)

		assert.Error(test, resultError)
		assert.NotNil(test, resultError)
		assert.Equal(test, "Error getting user by ID: test-error", resultError.Error())
	})
	test.Run("VerifyEmail_Get_User_Already_Verified_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)

		testToken := model.NewToken(newRefreshTokenValue)
		testUser := model.NewUser()
		testUser.AccountStatus = model.AccountStatusVerified

		mocks.MockTokenService.EXPECT().VerifyEmailVerificationToken(gomock.Any(), testToken.Token).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)

		// Test Verify
		resultError := mocks.AuthenticationService.VerifyEmail(context.Background(), testToken.Token)

		assert.Error(test, resultError)
		assert.IsType(test, &Error{}, resultError)
		assert.Equal(test, "Email already verified", resultError.Error())
	})
	test.Run("VerifyEmail_Update_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)

		testToken := model.NewToken(newRefreshTokenValue)
		testUser := model.NewUser()

		mocks.MockTokenService.EXPECT().VerifyEmailVerificationToken(gomock.Any(), testToken.Token).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)
		mocks.MockUserRepo.EXPECT().UpdateStatus(gomock.Any(), testUser).Return(errExample)

		// Act
		resultError := mocks.AuthenticationService.VerifyEmail(context.Background(), testToken.Token)

		// Assert
		assert.Error(test, resultError)
		assert.Equal(test, "Error updating user: test-error", resultError.Error())
	})

	test.Run("VerifyEmail_RemoveToken_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)

		testToken := model.NewToken(newRefreshTokenValue)
		testUser := model.NewUser()

		mocks.MockTokenService.EXPECT().VerifyEmailVerificationToken(gomock.Any(), testToken.Token).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)
		mocks.MockUserRepo.EXPECT().UpdateStatus(gomock.Any(), testUser).Return(nil)
		mocks.MockTokenService.EXPECT().RemoveUsedToken(gomock.Any(), testToken.Token).Return(errExample)

		// Act
		resultError := mocks.AuthenticationService.VerifyEmail(context.Background(), testToken.Token)

		// Assert
		assert.Error(test, resultError)
		assert.Equal(test, "test-error", resultError.Error())
	})

	// Authenticate
	test.Run("Authenticate_GetByEmail_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		email := "test@example.com"
		errorMessage := "Database error"
		errorExample := errors.New(errorMessage)

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), email).Return(nil, errorExample)
		logMock.EXPECT().Error(errorExample, "Error getting user by email")

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		// Test Authenticate
		user, err := mocks.AuthenticationService.Authenticate(ctx, email, "password")

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error getting user by email", err.Error())
		assert.Nil(test, user)
	})
	test.Run("Authenticate_User_Not_Found", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		email := "test@example.com"
		password := "password"

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), email).Return(nil, nil)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		// Test Authenticate
		user, err := mocks.AuthenticationService.Authenticate(ctx, email, password)

		assert.Error(test, err)
		assert.Equal(test, "Wrong Email", err.Error())
		assert.Nil(test, user)
	})
	test.Run("Authenticate_Invalid_Password", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		email := "test@example.com"

		user := model.NewUser()
		invalidPassword := "invalidpassword"

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), email).Return(user, nil)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)
		// Test Authenticate
		resultUser, resultError := mocks.AuthenticationService.Authenticate(ctx, email, invalidPassword)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, resultUser)
		assert.Equal(test, "Wrong Password", resultError.Error())
	})
	test.Run("Authenticate_AuthToken_Signing_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		user := model.NewUser()
		user.PasswordHash = "$2a$10$b4R.rxNHsELRW/JaqI1kS.CXO.xVamz.rwFXxchWD2pdKhKzZp94u"
		user.PasswordSalt = "7jQQnlalvK1E0iDzugF18ewa1Auf7R71Dr6OWnJbZbI="

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(user, nil)
		mocks.MockTokenService.EXPECT().CreateJWTTokens(gomock.Any(), user, nil).Return(nil, errExample)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)
		// Test Authenticate
		resultUser, resultError := mocks.AuthenticationService.Authenticate(
			ctx,
			testEmail,
			testPassword,
		)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, resultUser)
		assert.Equal(test, "test-error", resultError.Error())
	})
	// 	test.Run("Authenticate_AuthToken_Signing_Error", func(test *testing.T) {
	// 		// Arrange
	// 		controller := gomock.NewController(test)
	// 		defer controller.Finish()

	// 		mockUserRepo,
	// 			_,
	// 			_,
	// 			mockJWTSigner,
	// 			authenticationService := createAuthenticationService(controller)
	// 		logMock := loggerMock.NewMockLoggerer(controller)

	// 		user := model.NewUser()
	// 		user.PasswordHash = "$2a$10$b4R.rxNHsELRW/JaqI1kS.CXO.xVamz.rwFXxchWD2pdKhKzZp94u"
	// 		user.PasswordSalt = "7jQQnlalvK1E0iDzugF18ewa1Auf7R71Dr6OWnJbZbI="
	// 		error := errors.New("some error")

	// 		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(user, nil)
	// 		mockJWTSigner.EXPECT().SignToken(
	// 			gomock.Any(),
	// 			gomock.Any(),
	// 			commonJWT.AccessTokenType,
	// 		).Return(nil, error)
	// 		logMock.EXPECT().Error(error, "Error creating jwt token")

	// 		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

	// 		// Test Authenticate
	// 		resultUser, resultError := authenticationService.Authenticate(
	// 			ctx,
	// 			testEmail,
	// 			testPassword,
	// 		)

	// 		// Assert
	// 		assert.Error(test, resultError)
	// 		assert.Nil(test, resultUser)
	// 		assert.Equal(test, "Error creating authentication token", resultError.Error())
	// 	})
	// 	test.Run("Authenticate_Insert_Token_Error", func(test *testing.T) {
	// 		// Arrange
	// 		controller := gomock.NewController(test)
	// 		defer controller.Finish()

	// 		mockUserRepo,
	// 			mockTokenRepo,
	// 			_,
	// 			mockJWTSigner,
	// 			authenticationService := createAuthenticationService(controller)
	// 		logMock := loggerMock.NewMockLoggerer(controller)

	// 		user := model.NewUser()
	// 		user.PasswordHash = "$2a$10$b4R.rxNHsELRW/JaqI1kS.CXO.xVamz.rwFXxchWD2pdKhKzZp94u"
	// 		user.PasswordSalt = "7jQQnlalvK1E0iDzugF18ewa1Auf7R71Dr6OWnJbZbI="
	// 		errExample := errors.New("some error")

	// 		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(user, nil)
	// 		mockJWTSigner.EXPECT().SignToken(gomock.Any(), gomock.Any(), commonJWT.AccessTokenType).Return(&token, nil)
	// 		mockJWTSigner.EXPECT().SignToken(gomock.Any(), gomock.Any(), commonJWT.RefreshTokenType).Return(&refreshToken, nil)
	// 		mockTokenRepo.EXPECT().InsertToken(gomock.Any(), gomock.Any()).Return(nil, errExample)

	// 		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

	// 		// Act
	// 		resultUser, resultError := authenticationService.Authenticate(ctx, testEmail, testPassword)

	// 		// Assert
	// 		assert.Error(test, resultError)
	// 		assert.Nil(test, resultUser)
	// 		assert.Equal(test, "Could not insert new refresh token in DB: some error", resultError.Error())
	// 	})
	test.Run("Authenticate_Authenticate_Success", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		user := model.NewUser()
		user.PasswordHash = "$2a$10$b4R.rxNHsELRW/JaqI1kS.CXO.xVamz.rwFXxchWD2pdKhKzZp94u"
		user.PasswordSalt = "7jQQnlalvK1E0iDzugF18ewa1Auf7R71Dr6OWnJbZbI="
		tokenResponse := &model.AuthTokensResponse{
			AuthToken:    "test",
			RefreshToken: "test",
		}

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(user, nil)
		mocks.MockTokenService.EXPECT().CreateJWTTokens(gomock.Any(), user, nil).Return(tokenResponse, nil)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		// Act
		tokens, resultError := mocks.AuthenticationService.Authenticate(ctx, testEmail, testPassword)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, tokens)
		assert.Equal(test, "test", tokens.AuthToken)
		assert.Equal(test, "test", tokens.RefreshToken)
	})

	// // ResendEmailVerification
	test.Run("ResendEmailVerification_GetByEmail_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)

		errExample := errors.New("User repository error")

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, errExample)

		// Act
		err := mocks.AuthenticationService.ResendEmailVerification(context.Background(), testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error getting user by email: User repository error", err.Error())
	})

	test.Run("ResendEmailVerification_GetByEmail_NotFound", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, nil)

		// Act
		err := mocks.AuthenticationService.ResendEmailVerification(context.Background(), testEmail)

		// Assert
		assert.Error(test, err)
		assert.IsType(test, &Error{}, err)
		assert.Contains(test, err.Error(), "Invalid email")
	})

	test.Run("ResendEmailVerification_GetByEmail_AlreadyVerified", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		user := model.NewUser()
		user.AccountStatus = model.AccountStatusVerified

		mocks := createAuthenticationService(controller)

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(user, nil)

		// Act
		err := mocks.AuthenticationService.ResendEmailVerification(context.Background(), testEmail)

		// Assert
		assert.Error(test, err)
		assert.IsType(test, &Error{}, err)
		assert.Contains(test, err.Error(), "Email already verified")
	})

	test.Run("ResendEmailVerification_UserUpdate_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)

		testUser := model.NewUser()

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)
		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(gomock.Any(), testUser.ID).Return(nil, errExample)

		// Act
		err := mocks.AuthenticationService.ResendEmailVerification(context.Background(), testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "test-error", err.Error())
	})

	test.Run("ResendEmailVerification_SendEmail_Error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)

		testUser := model.NewUser()
		errExample := errors.New("Email service error")

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)
		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(gomock.Any(), testUser.ID).Return(&testTokenValue, nil)
		mocks.MockEmailService.EXPECT().SendVerificationMail(
			context.Background(),
			testEmail,
			testUser.FirstName,
			testTokenValue,
		).Return(errExample)

		// Act
		err := mocks.AuthenticationService.ResendEmailVerification(context.Background(), testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error sending verification email: Email service error", err.Error())
	})

	test.Run("ResendEmailVerification_Success", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)

		testUser := model.NewUser()

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)
		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(gomock.Any(), testUser.ID).Return(&testTokenValue, nil)
		mocks.MockEmailService.EXPECT().SendVerificationMail(
			context.Background(),
			testEmail,
			testUser.FirstName,
			testTokenValue,
		).Return(nil)

		// Act
		err := mocks.AuthenticationService.ResendEmailVerification(context.Background(), testEmail)

		// Assert
		assert.NoError(test, err)
	})

	// RefreshToken
	test.Run("RefreshToken_VerifyToken_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		token := "test-token"
		errorMessage := "Database error"
		errorExample := errors.New(errorMessage)

		mocks.MockTokenService.EXPECT().VerifyJWTToken(gomock.Any(), token).Return(nil, errorExample)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		// Test RefreshToken
		user, err := mocks.AuthenticationService.RefreshToken(ctx, token)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, errorExample.Error(), err.Error())
		assert.Nil(test, user)
	})

	// 	test.Run("RefreshToken_GetByEmail_error", func(test *testing.T) {
	// 		// Arrange
	// 		controller := gomock.NewController(test)
	// 		defer controller.Finish()

	// 		_,
	// 			_,
	// 			_,
	// 			mockJWTAuthenticator,
	// 			authenticationService := createAuthenticationService(controller)
	// 		logMock := loggerMock.NewMockLoggerer(controller)

	// 		token := "test_token"
	// 		errorMessage := "Database error"
	// 		errorExample := errors.New(errorMessage)

	// 		mockJWTAuthenticator.EXPECT().VerifyToken(token).Return(&jwt.Token{}, nil)
	// 		mockJWTAuthenticator.EXPECT().GetEmailFromToken(gomock.Any()).Return(nil, errorExample)
	// 		logMock.EXPECT().Error(errorExample, "Error getting email from token")

	// 		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

	// 		// Test RefreshToken
	// 		user, err := authenticationService.RefreshToken(ctx, token)

	// 		// Assert
	// 		assert.Error(test, err)
	// 		assert.Equal(test, "Error getting email from token", err.Error())
	// 		assert.Nil(test, user)
	// 	})
	test.Run("RefreshToken_User_Not_Found", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		token := "test_token"
		email := "email@example.com"
		errorMessage := "Database error"
		errorExample := errors.New(errorMessage)

		mocks.MockTokenService.EXPECT().VerifyJWTToken(gomock.Any(), token).Return(&email, nil)
		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), email).Return(nil, errorExample)
		logMock.EXPECT().Error(errorExample, "Error getting user by email")

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		// Test RefreshToken
		user, err := mocks.AuthenticationService.RefreshToken(ctx, token)

		assert.Error(test, err)
		assert.Equal(test, "Error getting user by email", err.Error())
		assert.Nil(test, user)
	})

	// 	test.Run("RefreshToken_Token_Not_Listed", func(test *testing.T) {
	// 		// Arrange
	// 		controller := gomock.NewController(test)
	// 		defer controller.Finish()

	// 		mockUserRepository,
	// 			mockTokenRepository,
	// 			_,
	// 			mockJWTSigner,
	// 			authenticationService := createAuthenticationService(controller)
	// 		logMock := loggerMock.NewMockLoggerer(controller)

	// 		token := "test_token"
	// 		jwtToken := &jwt.Token{}
	// 		email := "email@example.com"
	// 		user := model.NewUser()
	// 		errExample := errors.New("Custom error: Token not listed")

	// 		mockJWTSigner.EXPECT().VerifyToken(token).Return(jwtToken, nil)
	// 		mockJWTSigner.EXPECT().GetEmailFromToken(jwtToken).Return(&email, nil)
	// 		mockUserRepository.EXPECT().GetByEmail(gomock.Any(), email).Return(user, nil)
	// 		mockJWTSigner.EXPECT().SignToken(gomock.Any(), gomock.Any(), commonJWT.AccessTokenType).Return(&token, nil)
	// 		mockJWTSigner.EXPECT().SignToken(gomock.Any(), gomock.Any(), commonJWT.RefreshTokenType).Return(&refreshToken, nil)
	// 		mockTokenRepository.EXPECT().Remove(gomock.Any(), token).Return(errExample)

	// 		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

	// 		// Test RefreshToken
	// 		resultUser, resultError := authenticationService.RefreshToken(ctx, token)

	// 		// Assert
	// 		assert.Error(test, resultError)
	// 		assert.Equal(test, resultError.Error(), "Refresh token is not listed in DB: Custom error: Token not listed")
	// 		assert.Nil(test, resultUser)
	// 	})

	// 	test.Run("RefreshToken_Insert_Token_Error", func(test *testing.T) {
	// 		// Arrange
	// 		controller := gomock.NewController(test)
	// 		defer controller.Finish()

	// 		mockUserRepository,
	// 			mockTokenRepository,
	// 			_,
	// 			mockJWTSigner,
	// 			authenticationService := createAuthenticationService(controller)
	// 		logMock := loggerMock.NewMockLoggerer(controller)

	// 		jwtToken := &jwt.Token{}
	// 		email := "email@example.com"
	// 		user := model.NewUser()
	// 		errExample := errors.New("new error")

	// 		mockJWTSigner.EXPECT().VerifyToken(refreshToken).Return(jwtToken, nil)
	// 		mockJWTSigner.EXPECT().GetEmailFromToken(jwtToken).Return(&email, nil)
	// 		mockUserRepository.EXPECT().GetByEmail(gomock.Any(), email).Return(user, nil)
	// 		mockJWTSigner.EXPECT().SignToken(gomock.Any(), gomock.Any(), commonJWT.AccessTokenType).Return(&newRefreshTokenValue, nil)
	// 		mockJWTSigner.EXPECT().SignToken(gomock.Any(), gomock.Any(), commonJWT.RefreshTokenType).Return(&newRefreshTokenValue, nil)
	// 		mockTokenRepository.EXPECT().Remove(gomock.Any(), refreshToken).Return(nil)
	// 		mockTokenRepository.EXPECT().InsertToken(gomock.Any(), gomock.Any()).Return(nil, errExample)

	// 		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

	// 		// Test RefreshToken
	// 		resultUser, resultError := authenticationService.RefreshToken(ctx, refreshToken)

	// 		// Assert
	// 		assert.Error(test, resultError)
	// 		assert.Equal(test, "Could not insert new refresh token in DB: new error", resultError.Error())
	// 		assert.Nil(test, resultUser)
	// 	})

	test.Run("RefreshToken_Success", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		email := "email@example.com"
		user := model.NewUser()
		tokenResponse := &model.AuthTokensResponse{
			AuthToken:    "test",
			RefreshToken: "test",
		}

		mocks.MockTokenService.EXPECT().VerifyJWTToken(gomock.Any(), refreshTokenValue).Return(&email, nil)
		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), email).Return(user, nil)
		mocks.MockTokenService.EXPECT().CreateJWTTokens(gomock.Any(), user, &refreshTokenValue).Return(tokenResponse, nil)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		// Test RefreshToken
		resultUser, resultError := mocks.AuthenticationService.RefreshToken(ctx, refreshTokenValue)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, resultUser)
		assert.Equal(test, testEmail, user.Email)
	})

	// 	test.Run("ForgotPassword_InsertToken_Error", func(test *testing.T) {
	// 		controller := gomock.NewController(test)
	// 		defer controller.Finish()

	// 		mockUserRepo,
	// 			mockTokenRepo,
	// 			_,
	// 			_,
	// 			authenticationService := createAuthenticationService(controller)

	// 		testUser := model.NewUser()
	// 		testUser.AccountStatus = model.AccountStatusVerified

	// 		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)
	// 		mockTokenRepo.EXPECT().InsertToken(gomock.Any(), gomock.Any()).Return(nil, errExample)

	// 		// Act
	// 		err := authenticationService.ForgotPassword(context.Background(), testEmail)

	// 		// Assert
	// 		assert.Error(test, err)
	// 		assert.Equal(test, "Error inserting token in db: test-error", err.Error())
	// 	})

	// 	// VerifyResetPasswordToken
	// 	test.Run("VerifyResetPasswordToken_Success", func(test *testing.T) {
	// 		controller := gomock.NewController(test)
	// 		defer controller.Finish()

	// 		_,
	// 			mockTokenRepo,
	// 			_,
	// 			_,
	// 			authenticationService := createAuthenticationService(controller)

	// 		testTokenValue := "test-token"
	// 		testToken := model.NewToken(testTokenValue)
	// 		testToken.Type = commonJWT.ResetPasswordTokenType

	// 		mockTokenRepo.EXPECT().GetByToken(gomock.Any(), testTokenValue).Return(testToken, nil)

	// 		// Act
	// 		err := authenticationService.VerifyResetPasswordToken(context.Background(), testTokenValue)

	// 		// Assert
	// 		assert.NoError(test, err)
	// 	})

	// 	test.Run("VerifyResetPasswordToken_Expired_Error", func(test *testing.T) {
	// 		controller := gomock.NewController(test)
	// 		defer controller.Finish()

	// 		_,
	// 			mockTokenRepo,
	// 			_,
	// 			_,
	// 			authenticationService := createAuthenticationService(controller)

	// 		testTokenValue := "test-token"
	// 		testToken := model.NewToken(testTokenValue)
	// 		testToken.Type = commonJWT.ResetPasswordTokenType
	// 		testToken.ExpiresAt = time.Now().Add(-1 * time.Second)

	// 		mockTokenRepo.EXPECT().GetByToken(gomock.Any(), testTokenValue).Return(testToken, nil)

	// 		// Act
	// 		err := authenticationService.VerifyResetPasswordToken(context.Background(), testTokenValue)

	// 		// Assert
	// 		assert.Error(test, err)
	// 		assert.Equal(test, "Token expired", err.Error())
	// 	})

	// 	test.Run("VerifyResetPasswordToken_TokenType_Error", func(test *testing.T) {
	// 		controller := gomock.NewController(test)
	// 		defer controller.Finish()

	// 		_,
	// 			mockTokenRepo,
	// 			_,
	// 			_,
	// 			authenticationService := createAuthenticationService(controller)

	// 		testTokenValue := "test-token"
	// 		testToken := model.NewToken(testTokenValue)

	// 		mockTokenRepo.EXPECT().GetByToken(gomock.Any(), testTokenValue).Return(testToken, nil)

	// 		// Act
	// 		err := authenticationService.VerifyResetPasswordToken(context.Background(), testTokenValue)

	// 		// Assert
	// 		assert.Error(test, err)
	// 		assert.Equal(test, "Invalid token type", err.Error())
	// 	})

	// 	test.Run("VerifyResetPasswordToken_MissingToken_Error", func(test *testing.T) {
	// 		controller := gomock.NewController(test)
	// 		defer controller.Finish()

	// 		_,
	// 			mockTokenRepo,
	// 			_,
	// 			_,
	// 			authenticationService := createAuthenticationService(controller)

	// 		testTokenValue := "test-token"

	// 		mockTokenRepo.EXPECT().GetByToken(gomock.Any(), testTokenValue).Return(nil, errExample)

	// 		// Act
	// 		err := authenticationService.VerifyResetPasswordToken(context.Background(), testTokenValue)

	// 		// Assert
	// 		assert.Error(test, err)
	// 		assert.Equal(test, "Error getting token by its value: test-error", err.Error())
	// 	})

}

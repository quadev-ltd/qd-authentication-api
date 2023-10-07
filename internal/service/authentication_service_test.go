package service

import (
	"errors"
	"qd_authentication_api/internal/model"
	userRepositoryMock "qd_authentication_api/internal/repository/mock"
	serviceMock "qd_authentication_api/internal/service/mock"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

const (
	testEmail     = "test@example.com"
	testPassword  = "password"
	testFirstName = "John"
	testLastName  = "Doe"
)

// TODO try to use suite.Suite
var (
	testDateOfBirth = time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	token           = "token"
	refreshToken    = "refreshToken"
)

func newUser() *model.User {
	return &model.User{
		Email:                       "test@example.com",
		VerificationToken:           "token",
		VerificationTokenExpiryDate: time.Now().Add(10 * time.Minute),
		PasswordHash:                "hash",
		PasswordSalt:                "salt",
		FirstName:                   "Test",
		LastName:                    "User",
		DateOfBirth:                 time.Now(),
		RegistrationDate:            time.Now(),
		LastLoginDate:               time.Now(),
		AccountStatus:               model.AccountStatusUnverified,
	}
}

// TODO: Refactor this test to avoid duplication of code

func createauthenticationService(controller *gomock.Controller) (
	*userRepositoryMock.MockUserRepository,
	serviceMock.MockEmailServicer,
	serviceMock.MockJWTAthenticatorer,
	AuthenticationServicer,
) {
	mockRepo := userRepositoryMock.NewMockUserRepository(controller)
	mockEmail := serviceMock.NewMockEmailServicer(controller)
	mockJWTAuthenticator := serviceMock.NewMockJWTAthenticatorer(controller)
	authenticationService := NewAuthenticationService(mockEmail, mockRepo, mockJWTAuthenticator)

	return mockRepo, *mockEmail, *mockJWTAuthenticator, authenticationService
}

func TestAuthenticationService(test *testing.T) {
	// Register
	test.Run("Register_Success", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepo,
			mockEmail,
			_,
			authenticationService := createauthenticationService(controller)

		mockRepo.EXPECT().GetByEmail(testEmail).Return(nil, nil)
		mockRepo.EXPECT().Create(gomock.Any()).Return(nil)
		mockEmail.EXPECT().SendVerificationMail(testEmail, testFirstName, gomock.Any()).Return(nil)

		// Test successful registration
		err := authenticationService.Register(testEmail, testPassword, testFirstName, testLastName, &testDateOfBirth)
		assert.NoError(test, err)
	})
	test.Run("Register_Email_Uniqueness", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepo,
			_,
			_,
			authenticationService := createauthenticationService(controller)

		mockRepo.EXPECT().GetByEmail(testEmail).Return(&model.User{}, nil)

		err := authenticationService.Register(testEmail, testPassword, testFirstName, testLastName, &testDateOfBirth)

		assert.Error(test, err)

		assert.Equal(test, (&model.EmailInUseError{Email: testEmail}).Error(), err.Error())
	})
	test.Run("Register_Invalid_Email", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()
		mockRepo,
			_,
			_,
			authenticationService := createauthenticationService(controller)
		invalidEmail := "invalid-email"

		mockRepo.EXPECT().GetByEmail(invalidEmail).Return(nil, nil)

		err := authenticationService.Register(invalidEmail, testPassword, testFirstName, testLastName, &testDateOfBirth)

		assert.Error(test, err)
		assert.Contains(test, err.Error(), "Email")
	})
	test.Run("Register_Invalid_DOB", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepo,
			_,
			_,
			authenticationService := createauthenticationService(controller)
		invalidDateOfBirth := time.Time{}

		mockRepo.EXPECT().GetByEmail(testEmail).Return(nil, nil)

		err := authenticationService.Register(testEmail, testPassword, testFirstName, testLastName, &invalidDateOfBirth)

		assert.Error(test, err)
		assert.Contains(test, err.Error(), "DateOfBirth")
	})
	test.Run("Register_Send_email_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()
		mockedError := errors.New("Test error")

		mockRepo,
			mockEmail,
			_,
			authenticationService := createauthenticationService(controller)

		mockRepo.EXPECT().GetByEmail(testEmail).Return(nil, nil)
		mockRepo.EXPECT().Create(gomock.Any()).Return(nil)
		mockEmail.EXPECT().SendVerificationMail(testEmail, testFirstName, gomock.Any()).Return(mockedError)

		// Test successful registration
		error := authenticationService.Register(testEmail, testPassword, testFirstName, testLastName, &testDateOfBirth)
		assert.Error(test, error)
		assert.Equal(test, mockedError.Error(), error.Error())
	})

	// Verify
	test.Run("Verify_Verify_Success", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepo,
			_,
			_,
			authenticationService := createauthenticationService(controller)

		verificationToken := "testToken"
		testUser := newUser()

		mockRepo.EXPECT().GetByVerificationToken(verificationToken).Return(testUser, nil)
		mockRepo.EXPECT().Update(testUser).Return(nil)

		// Test successful verification
		err := authenticationService.VerifyEmail(verificationToken)

		assert.NoError(test, err)
		assert.Equal(test, model.AccountStatusVerified, testUser.AccountStatus)
	})
	test.Run("Verify_Token_expired_error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepo,
			_,
			_,
			authenticationService := createauthenticationService(controller)

		expiredToken := "expired_token"
		user := newUser()
		user.VerificationToken = expiredToken
		user.VerificationTokenExpiryDate = time.Now().Add(-VerificationTokenExpiry - time.Hour)

		mockRepo.EXPECT().GetByVerificationToken(expiredToken).Return(user, nil)

		err := authenticationService.VerifyEmail(expiredToken)

		assert.NotNil(test, err)
		assert.Error(test, err)
		assert.Contains(test, err.Error(), "Verification token expired")

	})
	test.Run("Verify_Returns_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepo,
			_,
			_,
			authenticationService := createauthenticationService(controller)

		verificationToken := "testToken"
		mockedError := errors.New("Test error")

		mockRepo.EXPECT().GetByVerificationToken(verificationToken).Return(nil, mockedError)

		// Test Verify
		resultError := authenticationService.VerifyEmail(verificationToken)

		assert.Error(test, resultError)
		assert.Equal(test, mockedError.Error(), resultError.Error())
	})
	test.Run("Verify_Token_not_found_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepo,
			_,
			_,
			authenticationService := createauthenticationService(controller)

		verificationToken := "testToken"

		mockRepo.EXPECT().GetByVerificationToken(verificationToken).Return(nil, nil)

		// Test Verify
		resultError := authenticationService.VerifyEmail(verificationToken)

		assert.Error(test, resultError)
		assert.NotNil(test, resultError)
		assert.Equal(test, "Invalid verification token", resultError.Error())
	})
	test.Run("Verify_Update_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepo,
			_,
			_,
			authenticationService := createauthenticationService(controller)

		testToken := "testToken"

		user := newUser()

		mockRepo.EXPECT().GetByVerificationToken(testToken).Return(user, nil)
		mockRepo.EXPECT().Update(user).Return(errors.New("update error"))

		// Act
		resultError := authenticationService.VerifyEmail(testToken)

		// Assert
		assert.Error(test, resultError)
		assert.Equal(test, "update error", resultError.Error())
	})

	// Authenticate
	test.Run("Authenticate_GetByEmail_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepo,
			_,
			_,
			authenticationService := createauthenticationService(controller)

		email := "test@example.com"
		errorMessage := "Database error"

		mockRepo.EXPECT().GetByEmail(email).Return(nil, errors.New(errorMessage))

		// Test Authenticate
		user, err := authenticationService.Authenticate(email, "password")

		// Assert
		assert.Error(test, err)
		assert.Equal(test, errorMessage, err.Error())
		assert.Nil(test, user)
	})
	test.Run("Authenticate_User_Not_Found", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepo,
			_,
			_,
			authenticationService := createauthenticationService(controller)

		email := "test@example.com"
		password := "password"

		mockRepo.EXPECT().GetByEmail(email).Return(nil, nil)

		// Test Authenticate
		user, err := authenticationService.Authenticate(email, password)

		assert.Error(test, err)
		assert.Equal(test, "Wrong Email", err.Error())
		assert.Nil(test, user)
	})
	test.Run("Authenticate_Invalid_Password", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepo,
			_,
			_,
			authenticationService := createauthenticationService(controller)

		email := "test@example.com"

		user := newUser()
		invalidPassword := "invalidpassword"

		mockRepo.EXPECT().GetByEmail(email).Return(user, nil)

		// Test Authenticate
		resultUser, resultError := authenticationService.Authenticate(email, invalidPassword)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, resultUser)
		assert.Equal(test, "Wrong Password", resultError.Error())
	})
	test.Run("Authenticate_AuthToken Signing Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepo,
			_,
			mockJWTAuthenticator,
			authenticationService := createauthenticationService(controller)

		user := newUser()
		user.PasswordHash = "$2a$10$nUXvSYPaNFSjlt2w/buFQen6w90hNdLkdRo0mqUZxXkWcMt0lb1uW"
		user.PasswordSalt = "salt"

		mockRepo.EXPECT().GetByEmail(testEmail).Return(user, nil)
		mockJWTAuthenticator.EXPECT().SignToken(
			gomock.Any(),
			gomock.Any(),
		).Return(nil, errors.New("some error"))

		// Test Authenticate
		resultUser, resultError := authenticationService.Authenticate(testEmail, testPassword)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, resultUser)
		assert.Equal(test, "Error creating authentication token.", resultError.Error())
	})
	test.Run("Authenticate_Authenticate_Success", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepo,
			_,
			mockJWTAuthenticator,
			authenticationService := createauthenticationService(controller)

		user := newUser()
		user.PasswordHash = "$2a$10$nUXvSYPaNFSjlt2w/buFQen6w90hNdLkdRo0mqUZxXkWcMt0lb1uW"
		user.PasswordSalt = "salt"

		mockRepo.EXPECT().GetByEmail(testEmail).Return(user, nil)
		mockJWTAuthenticator.EXPECT().SignToken(gomock.Any(), gomock.Any()).Return(&token, nil)
		mockJWTAuthenticator.EXPECT().SignToken(gomock.Any(), gomock.Any()).Return(&refreshToken, nil)

		// Act
		resultUser, resultError := authenticationService.Authenticate(testEmail, testPassword)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, resultUser)
		assert.Equal(test, testEmail, resultUser.UserEmail)
	})

	// VerifyTokenAndDecodeEmail
	test.Run("VerifyTokenAndDecodeEmail_VerifyToken_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		_, _, mockJWTAuthenticator, authenticationService := createauthenticationService(controller)

		token := "invalid-token"
		mockedError := errors.New("Token verification failed")

		mockJWTAuthenticator.EXPECT().VerifyToken(token).Return(nil, mockedError)

		// Act
		email, err := authenticationService.VerifyTokenAndDecodeEmail(token)

		// Assert
		assert.Error(test, err)
		assert.Nil(test, email)
		assert.Equal(test, mockedError.Error(), err.Error())
	})

	test.Run("VerifyTokenAndDecodeEmail_GetEmailFromToken_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		_, _, mockJWTAuthenticator, authenticationService := createauthenticationService(controller)

		token := "valid-token"
		mockedError := errors.New("Error decoding email")

		mockJWTAuthenticator.EXPECT().VerifyToken(token).Return(&jwt.Token{}, nil)
		mockJWTAuthenticator.EXPECT().GetEmailFromToken(gomock.Any()).Return(nil, mockedError)

		// Act
		email, err := authenticationService.VerifyTokenAndDecodeEmail(token)

		// Assert
		assert.Error(test, err)
		assert.Nil(test, email)
		assert.Equal(test, mockedError.Error(), err.Error())
	})

	test.Run("VerifyTokenAndDecodeEmail_Success", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		_, _, mockJWTAuthenticator, authenticationService := createauthenticationService(controller)

		exampleEmail := "example@email.com"
		token := "valid-token"
		jwtToken := jwt.Token{}
		mockJWTAuthenticator.EXPECT().VerifyToken(token).Return(&jwtToken, nil)
		mockJWTAuthenticator.EXPECT().GetEmailFromToken(&jwtToken).Return(&exampleEmail, nil)

		// Act
		email, err := authenticationService.VerifyTokenAndDecodeEmail(token)

		// Assert
		assert.NoError(test, err)
		assert.NotNil(test, email)
		assert.Equal(test, exampleEmail, *email)
	})

	// ResendEmailVerification
	test.Run("ResendEmailVerification_GetByEmail_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepo,
			_,
			_,
			authenticationService := createauthenticationService(controller)

		expectedError := errors.New("User repository error")

		mockRepo.EXPECT().GetByEmail(testEmail).Return(nil, expectedError)

		// Act
		err := authenticationService.ResendEmailVerification(testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, expectedError, err)
	})

	test.Run("ResendEmailVerification_GetByEmail_NotFound", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepo,
			_,
			_,
			authenticationService := createauthenticationService(controller)

		mockRepo.EXPECT().GetByEmail(testEmail).Return(nil, nil)

		// Act
		err := authenticationService.ResendEmailVerification(testEmail)

		// Assert
		assert.Error(test, err)
		assert.IsType(test, &ServiceError{}, err)
		assert.Contains(test, err.Error(), "Invalid email")
	})

	test.Run("ResendEmailVerification_GetByEmail_AlreadyVerified", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		user := newUser()
		user.AccountStatus = model.AccountStatusVerified

		mockRepo,
			_,
			_,
			authenticationService := createauthenticationService(controller)

		mockRepo.EXPECT().GetByEmail(testEmail).Return(user, nil)

		// Act
		err := authenticationService.ResendEmailVerification(testEmail)

		// Assert
		assert.Error(test, err)
		assert.IsType(test, &ServiceError{}, err)
		assert.Contains(test, err.Error(), "Email already verified")
	})

	test.Run("ResendEmailVerification_UserUpdate_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepo,
			_,
			_,
			authenticationService := createauthenticationService(controller)

		testUser := newUser()
		expectedError := errors.New("Update error")

		mockRepo.EXPECT().GetByEmail(testEmail).Return(testUser, nil)
		mockRepo.EXPECT().Update(testUser).Return(expectedError)

		// Act
		err := authenticationService.ResendEmailVerification(testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, expectedError, err)
	})

	test.Run("ResendEmailVerification_SendEmail_Error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepo,
			mockEmail,
			_,
			authenticationService := createauthenticationService(controller)

		testUser := newUser()
		expectedError := errors.New("Email service error")

		mockRepo.EXPECT().GetByEmail(testEmail).Return(testUser, nil)
		mockRepo.EXPECT().Update(testUser).Return(nil)
		mockEmail.EXPECT().SendVerificationMail(testEmail, testUser.FirstName, gomock.Any()).Return(expectedError)

		// Act
		err := authenticationService.ResendEmailVerification(testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, expectedError, err)
	})

	test.Run("ResendEmailVerification_Success", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepo,
			mockEmail,
			_,
			authenticationService := createauthenticationService(controller)

		testUser := newUser()

		mockRepo.EXPECT().GetByEmail(testEmail).Return(testUser, nil)
		mockRepo.EXPECT().Update(testUser).Return(nil)
		mockEmail.EXPECT().SendVerificationMail(testEmail, testUser.FirstName, gomock.Any()).Return(nil)

		// Act
		err := authenticationService.ResendEmailVerification(testEmail)

		// Assert
		assert.NoError(test, err)
	})
}
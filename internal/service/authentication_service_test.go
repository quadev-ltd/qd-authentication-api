package service

import (
	"errors"
	"qd_authentication_api/internal/model"
	userRepositoryMock "qd_authentication_api/internal/repository/mock"
	emailServiceMock "qd_authentication_api/internal/service/mock"
	"testing"
	"time"

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
var testDateOfBirth = time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)

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

func TestAuthenticationService(test *testing.T) {
	// Register
	test.Run("Register_Success", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepo := userRepositoryMock.NewMockUserRepository(controller)
		mockEmail := emailServiceMock.NewMockEmailServicer(controller)
		authenticationService := NewAuthenticationService(mockEmail, mockRepo, "testKey")

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

		mockRepo := userRepositoryMock.NewMockUserRepository(controller)
		mockEmail := emailServiceMock.NewMockEmailServicer(controller)
		authenticationService := NewAuthenticationService(mockEmail, mockRepo, "testKey")

		mockRepo.EXPECT().GetByEmail(testEmail).Return(&model.User{}, nil)

		err := authenticationService.Register(testEmail, testPassword, testFirstName, testLastName, &testDateOfBirth)

		assert.Error(test, err)

		assert.Equal(test, (&model.EmailInUseError{Email: testEmail}).Error(), err.Error())
	})
	test.Run("Register_Invalid_Email", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()
		mockRepo := userRepositoryMock.NewMockUserRepository(controller)
		mockEmail := emailServiceMock.NewMockEmailServicer(controller)
		authenticationService := NewAuthenticationService(mockEmail, mockRepo, "testKey")
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

		mockRepo := userRepositoryMock.NewMockUserRepository(controller)
		mockEmail := emailServiceMock.NewMockEmailServicer(controller)
		authenticationService := NewAuthenticationService(mockEmail, mockRepo, "testKey")
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

		mockRepo := userRepositoryMock.NewMockUserRepository(controller)
		mockEmail := emailServiceMock.NewMockEmailServicer(controller)
		authenticationService := NewAuthenticationService(mockEmail, mockRepo, "testKey")

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

		mockRepo := userRepositoryMock.NewMockUserRepository(controller)
		mockEmail := emailServiceMock.NewMockEmailServicer(controller)
		authenticationService := NewAuthenticationService(mockEmail, mockRepo, "testKey")

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

		mockRepo := userRepositoryMock.NewMockUserRepository(controller)
		authenticationService := NewAuthenticationService(nil, mockRepo, "testKey")

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

		mockRepo := userRepositoryMock.NewMockUserRepository(controller)
		mockEmail := emailServiceMock.NewMockEmailServicer(controller)
		authenticationService := NewAuthenticationService(mockEmail, mockRepo, "testKey")

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

		mockRepo := userRepositoryMock.NewMockUserRepository(controller)
		mockEmail := emailServiceMock.NewMockEmailServicer(controller)
		authenticationService := NewAuthenticationService(mockEmail, mockRepo, "testKey")

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

		mockRepo := userRepositoryMock.NewMockUserRepository(controller)
		authenticationService := NewAuthenticationService(nil, mockRepo, "testKey")

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

		mockRepo := userRepositoryMock.NewMockUserRepository(controller)
		mockEmail := emailServiceMock.NewMockEmailServicer(controller)
		authenticationService := NewAuthenticationService(mockEmail, mockRepo, "testKey")

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

		mockRepo := userRepositoryMock.NewMockUserRepository(controller)
		authenticationService := NewAuthenticationService(nil, mockRepo, "testKey")

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

		mockRepo := userRepositoryMock.NewMockUserRepository(controller)
		authenticationService := NewAuthenticationService(nil, mockRepo, "testKey")

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
	// test.Run("Authenticate_AuthToken Signing Error", testAuthenticationService_Authenticate_AuthTokenSigningError)
	test.Run("Authenticate_Authenticate_Success", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepo := userRepositoryMock.NewMockUserRepository(controller)
		mockEmail := emailServiceMock.NewMockEmailServicer(controller)
		authenticationService := NewAuthenticationService(mockEmail, mockRepo, "testKey")

		testEmail := "test@example.com"
		testPassword := "password"

		user := newUser()
		user.PasswordHash = "$2a$10$nUXvSYPaNFSjlt2w/buFQen6w90hNdLkdRo0mqUZxXkWcMt0lb1uW"
		user.PasswordSalt = "salt"

		mockRepo.EXPECT().GetByEmail(testEmail).Return(user, nil)

		// Act
		resultUser, resultError := authenticationService.Authenticate(testEmail, testPassword)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, resultUser)
		assert.Equal(test, testEmail, resultUser.UserEmail)
	})
}

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

var testDateOfBirth = time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)

func newUser() *model.User {
	return &model.User{
		Email:             "test@example.com",
		VerificationToken: "token",
		PasswordHash:      "hash",
		PasswordSalt:      "salt",
		FirstName:         "Test",
		LastName:          "User",
		DateOfBirth:       time.Now(),
		RegistrationDate:  time.Now(),
		LastLoginDate:     time.Now(),
		AccountStatus:     model.AccountStatusUnverified,
	}
}

func testAuthenticationService_Register_Success(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()

	mockRepo := userRepositoryMock.NewMockUserRepository(controller)
	mockEmail := emailServiceMock.NewMockEmailServicer(controller)
	authenticationService := NewAuthenticationService(mockEmail, mockRepo)

	mockRepo.EXPECT().GetByEmail(testEmail).Return(nil, nil)
	mockRepo.EXPECT().Create(gomock.Any()).Return(nil)
	mockEmail.EXPECT().SendVerificationMail(testEmail, testFirstName, gomock.Any()).Return(nil)

	// Test successful registration
	err := authenticationService.Register(testEmail, testPassword, testFirstName, testLastName, &testDateOfBirth)
	assert.NoError(test, err)
}

func testAuthenticationService_Register_EmailUniqueness(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()

	mockRepo := userRepositoryMock.NewMockUserRepository(controller)
	mockEmail := emailServiceMock.NewMockEmailServicer(controller)
	authenticationService := NewAuthenticationService(mockEmail, mockRepo)

	mockRepo.EXPECT().GetByEmail(testEmail).Return(&model.User{}, nil)

	err := authenticationService.Register(testEmail, testPassword, testFirstName, testLastName, &testDateOfBirth)

	assert.Error(test, err)

	assert.Equal(test, (&model.EmailInUseError{Email: testEmail}).Error(), err.Error())
}

func testAuthenticationService_Register_InvalidEmail(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()
	mockRepo := userRepositoryMock.NewMockUserRepository(controller)
	mockEmail := emailServiceMock.NewMockEmailServicer(controller)
	authenticationService := NewAuthenticationService(mockEmail, mockRepo)
	invalidEmail := "invalid-email"

	mockRepo.EXPECT().GetByEmail(invalidEmail).Return(nil, nil)

	err := authenticationService.Register(invalidEmail, testPassword, testFirstName, testLastName, &testDateOfBirth)

	assert.Error(test, err)
	assert.Contains(test, err.Error(), "Email")
}

func testAuthenticationService_Register_InvalidDateOfBirth(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()

	mockRepo := userRepositoryMock.NewMockUserRepository(controller)
	mockEmail := emailServiceMock.NewMockEmailServicer(controller)
	authenticationService := NewAuthenticationService(mockEmail, mockRepo)
	invalidDateOfBirth := time.Time{}

	mockRepo.EXPECT().GetByEmail(testEmail).Return(nil, nil)

	err := authenticationService.Register(testEmail, testPassword, testFirstName, testLastName, &invalidDateOfBirth)

	assert.Error(test, err)
	assert.Contains(test, err.Error(), "DateOfBirth")
}

func testAuthenticationService_Register_SendEmailError(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()
	mockedError := errors.New("Test error")

	mockRepo := userRepositoryMock.NewMockUserRepository(controller)
	mockEmail := emailServiceMock.NewMockEmailServicer(controller)
	authenticationService := NewAuthenticationService(mockEmail, mockRepo)

	mockRepo.EXPECT().GetByEmail(testEmail).Return(nil, nil)
	mockRepo.EXPECT().Create(gomock.Any()).Return(nil)
	mockEmail.EXPECT().SendVerificationMail(testEmail, testFirstName, gomock.Any()).Return(mockedError)

	// Test successful registration
	error := authenticationService.Register(testEmail, testPassword, testFirstName, testLastName, &testDateOfBirth)
	assert.Error(test, error)
	assert.Equal(test, mockedError.Error(), error.Error())
}

func testAuthenticationService_Verify_Success(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()

	mockRepo := userRepositoryMock.NewMockUserRepository(controller)
	mockEmail := emailServiceMock.NewMockEmailServicer(controller)
	authenticationService := NewAuthenticationService(mockEmail, mockRepo)

	verificationToken := "testToken"
	testUser := newUser()

	mockRepo.EXPECT().GetByVerificationToken(verificationToken).Return(testUser, nil)
	mockRepo.EXPECT().Update(testUser).Return(nil)

	// Test successful verification
	err := authenticationService.Verify(verificationToken)

	assert.NoError(test, err)
	assert.Equal(test, model.AccountStatusVerified, testUser.AccountStatus)
}

func testAuthenticationService_Verify_GetByVerificationTokenError(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()

	mockRepo := userRepositoryMock.NewMockUserRepository(controller)
	mockEmail := emailServiceMock.NewMockEmailServicer(controller)
	authenticationService := NewAuthenticationService(mockEmail, mockRepo)

	verificationToken := "testToken"
	mockedError := errors.New("Test error")

	mockRepo.EXPECT().GetByVerificationToken(verificationToken).Return(nil, mockedError)

	// Test Verify
	resultError := authenticationService.Verify(verificationToken)

	assert.Error(test, resultError)
	assert.Equal(test, mockedError.Error(), resultError.Error())
}

func testAuthenticationService_Verify_UserNotFound(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()

	mockRepo := userRepositoryMock.NewMockUserRepository(controller)
	mockEmail := emailServiceMock.NewMockEmailServicer(controller)
	authenticationService := NewAuthenticationService(mockEmail, mockRepo)

	verificationToken := "testToken"

	mockRepo.EXPECT().GetByVerificationToken(verificationToken).Return(nil, nil)

	// Test Verify
	resultError := authenticationService.Verify(verificationToken)

	assert.Error(test, resultError)
	assert.Equal(test, "Invalid verification token", resultError.Error())
}

func testAuthenticationService_Verify_UpdateError(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()

	mockRepo := userRepositoryMock.NewMockUserRepository(controller)
	authenticationService := NewAuthenticationService(nil, mockRepo)

	testToken := "testToken"

	user := newUser()

	mockRepo.EXPECT().GetByVerificationToken(testToken).Return(user, nil)
	mockRepo.EXPECT().Update(user).Return(errors.New("update error"))

	// Act
	resultError := authenticationService.Verify(testToken)

	// Assert
	assert.Error(test, resultError)
	assert.Equal(test, "update error", resultError.Error())
}

func testAuthenticationService_Authenticate_GetByEmailError(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()

	mockRepo := userRepositoryMock.NewMockUserRepository(controller)
	mockEmail := emailServiceMock.NewMockEmailServicer(controller)
	authenticationService := NewAuthenticationService(mockEmail, mockRepo)

	email := "test@example.com"
	errorMessage := "Database error"

	mockRepo.EXPECT().GetByEmail(email).Return(nil, errors.New(errorMessage))

	// Test Authenticate
	user, err := authenticationService.Authenticate(email, "password")

	// Assert
	assert.Error(test, err)
	assert.Equal(test, errorMessage, err.Error())
	assert.Nil(test, user)
}

func testAuthenticationService_Authenticate_UserNotFound(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()

	mockRepo := userRepositoryMock.NewMockUserRepository(controller)
	authenticationService := NewAuthenticationService(nil, mockRepo)

	email := "test@example.com"
	password := "password"

	mockRepo.EXPECT().GetByEmail(email).Return(nil, nil)

	// Test Authenticate
	user, err := authenticationService.Authenticate(email, password)

	assert.Error(test, err)
	assert.Equal(test, "Wrong Email", err.Error())
	assert.Nil(test, user)
}

func testAuthenticationService_Authenticate_InvalidPassword(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()

	mockRepo := userRepositoryMock.NewMockUserRepository(controller)
	authenticationService := NewAuthenticationService(nil, mockRepo)

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
}

// TODO log the values of jwtSigningKey during this test
// func testAuthenticationService_Authenticate_AuthTokenSigningError(test *testing.T) {
// 	// Arrange
// 	controller := gomock.NewController(test)
// 	defer controller.Finish()

// 	mockRepo := userRepositoryMock.NewMockUserRepository(controller)
// 	authenticationService := NewAuthenticationService(nil, mockRepo)

// 	email := "test@example.com"
// 	password := "password"

// 	user := newUser()
// 	user.PasswordHash = "$2a$10$nUXvSYPaNFSjlt2w/buFQen6w90hNdLkdRo0mqUZxXkWcMt0lb1uW"
// 	user.PasswordSalt = "salt"

// 	mockRepo.EXPECT().GetByEmail(email).Return(user, nil)

// 	// Mock JWT signing key error
// 	oldSigningKey := jwtSigningKey
// 	defer func() {
// 		jwtSigningKey = oldSigningKey
// 	}()
// 	jwtSigningKey = []byte("invalid-key")

// 	// Test Authenticate
// 	resultUser, resultError := authenticationService.Authenticate(email, password)

// 	// Assert
// 	assert.Error(test, resultError)
// 	assert.Nil(test, resultUser)
// 	assert.Contains(test, resultError.Error(), "token signing")
// }

func testAuthenticationService_Authenticate_Success(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()

	mockRepo := userRepositoryMock.NewMockUserRepository(controller)
	mockEmail := emailServiceMock.NewMockEmailServicer(controller)
	authenticationService := NewAuthenticationService(mockEmail, mockRepo)

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
}

func TestAuthenticationService(test *testing.T) {
	// Register
	test.Run("Success", testAuthenticationService_Register_Success)
	test.Run("Email Uniqueness", testAuthenticationService_Register_EmailUniqueness)
	test.Run("Invalid Email", testAuthenticationService_Register_InvalidEmail)
	test.Run("Invalid Date Of Birth", testAuthenticationService_Register_InvalidDateOfBirth)
	test.Run("Send email error", testAuthenticationService_Register_SendEmailError)

	// Verify
	test.Run("Verify Success", testAuthenticationService_Verify_Success)
	test.Run("Returns error", testAuthenticationService_Verify_GetByVerificationTokenError)
	test.Run("Token not found error", testAuthenticationService_Verify_UserNotFound)
	test.Run("Update error", testAuthenticationService_Verify_UpdateError)

	// Authenticate
	test.Run("GetByEmail error", testAuthenticationService_Authenticate_GetByEmailError)
	test.Run("User Not Found", testAuthenticationService_Authenticate_UserNotFound)
	test.Run("Invalid Password", testAuthenticationService_Authenticate_InvalidPassword)
	// test.Run("AuthToken Signing Error", testAuthenticationService_Authenticate_AuthTokenSigningError)
	test.Run("Authenticate Success", testAuthenticationService_Authenticate_Success)
}

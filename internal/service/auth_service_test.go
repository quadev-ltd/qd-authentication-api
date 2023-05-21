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

func testAuthService_Register_Success(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()

	mockRepo := userRepositoryMock.NewMockUserRepository(controller)
	mockEmail := emailServiceMock.NewMockEmailServicer(controller)
	authService := NewAuthService(mockEmail, mockRepo)

	mockRepo.EXPECT().GetByEmail(testEmail).Return(nil, nil)
	mockRepo.EXPECT().Create(gomock.Any()).Return(nil)
	mockEmail.EXPECT().SendVerificationMail(testEmail, testFirstName, gomock.Any()).Return(nil)

	// Test successful registration
	err := authService.Register(testEmail, testPassword, testFirstName, testLastName, &testDateOfBirth)
	assert.NoError(test, err)
}

func testAuthService_Register_EmailUniqueness(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()

	mockRepo := userRepositoryMock.NewMockUserRepository(controller)
	mockEmail := emailServiceMock.NewMockEmailServicer(controller)
	authService := NewAuthService(mockEmail, mockRepo)

	mockRepo.EXPECT().GetByEmail(testEmail).Return(&model.User{}, nil)

	error := authService.Register(testEmail, testPassword, testFirstName, testLastName, &testDateOfBirth)

	assert.Error(test, error)

	assert.Equal(test, (&model.EmailInUseError{Email: testEmail}).Error(), error.Error())
}

func testAuthService_Register_InvalidEmail(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()
	mockRepo := userRepositoryMock.NewMockUserRepository(controller)
	mockEmail := emailServiceMock.NewMockEmailServicer(controller)
	authService := NewAuthService(mockEmail, mockRepo)
	invalidEmail := "invalid-email"

	mockRepo.EXPECT().GetByEmail(invalidEmail).Return(nil, nil)

	err := authService.Register(invalidEmail, testPassword, testFirstName, testLastName, &testDateOfBirth)

	assert.Error(test, err)
	assert.Contains(test, err.Error(), "Email")
}

func testAuthService_Register_InvalidDateOfBirth(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()

	mockRepo := userRepositoryMock.NewMockUserRepository(controller)
	mockEmail := emailServiceMock.NewMockEmailServicer(controller)
	authService := NewAuthService(mockEmail, mockRepo)
	invalidDateOfBirth := time.Time{}

	mockRepo.EXPECT().GetByEmail(testEmail).Return(nil, nil)

	err := authService.Register(testEmail, testPassword, testFirstName, testLastName, &invalidDateOfBirth)

	assert.Error(test, err)
	assert.Contains(test, err.Error(), "DateOfBirth")
}

func testAuthService_Register_SendEmailError(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()
	mockedError := errors.New("Test error")

	mockRepo := userRepositoryMock.NewMockUserRepository(controller)
	mockEmail := emailServiceMock.NewMockEmailServicer(controller)
	authService := NewAuthService(mockEmail, mockRepo)

	mockRepo.EXPECT().GetByEmail(testEmail).Return(nil, nil)
	mockRepo.EXPECT().Create(gomock.Any()).Return(nil)
	mockEmail.EXPECT().SendVerificationMail(testEmail, testFirstName, gomock.Any()).Return(mockedError)

	// Test successful registration
	error := authService.Register(testEmail, testPassword, testFirstName, testLastName, &testDateOfBirth)
	assert.Error(test, error)
	assert.Equal(test, mockedError.Error(), error.Error())
}

func TestAuthService_Register(test *testing.T) {
	// Run all the test functions
	test.Run("Success", testAuthService_Register_Success)
	test.Run("Email Uniqueness", testAuthService_Register_EmailUniqueness)
	test.Run("Invalid Email", testAuthService_Register_InvalidEmail)
	test.Run("Invalid Date Of Birth", testAuthService_Register_InvalidDateOfBirth)
	test.Run("Send email error", testAuthService_Register_SendEmailError)
}

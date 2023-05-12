package service

import (
	"errors"
	"qd_authentication_api/internal/repository"
	"testing"
	"time"

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
	mockRepo := &repository.MockUserRepository{}
	authService := NewAuthService(mockRepo)

	// Test successful registration
	err := authService.Register(testEmail, testPassword, testFirstName, testLastName, &testDateOfBirth)
	assert.NoError(test, err)
	assert.Len(test, mockRepo.Users, 1)
}

func testAuthService_Register_EmailUniqueness(test *testing.T) {
	mockRepo := &repository.MockUserRepository{}
	authService := NewAuthService(mockRepo)

	_ = authService.Register(testEmail, testPassword, testFirstName, testLastName, &testDateOfBirth)
	err := authService.Register(testEmail, testPassword, testFirstName, testLastName, &testDateOfBirth)
	assert.Error(test, err)
	assert.Equal(test, errors.New("email is already in use"), err)
}

func testAuthService_Register_InvalidEmail(test *testing.T) {
	mockRepo := &repository.MockUserRepository{}
	authService := NewAuthService(mockRepo)
	invalidEmail := "invalid-email"

	err := authService.Register(invalidEmail, testPassword, testFirstName, testLastName, &testDateOfBirth)
	assert.Error(test, err)
	assert.Contains(test, err.Error(), "Email")
}

func testAuthService_Register_InvalidDateOfBirth(test *testing.T) {
	mockRepo := &repository.MockUserRepository{}
	authService := NewAuthService(mockRepo)

	invalidDateOfBirth := time.Time{}

	err := authService.Register(testEmail, testPassword, testFirstName, testLastName, &invalidDateOfBirth)
	assert.Error(test, err)
	assert.Contains(test, err.Error(), "DateOfBirth")
}

func TestAuthService_Register(t *testing.T) {
	// Run all the test functions
	t.Run("Success", testAuthService_Register_Success)
	t.Run("Email Uniqueness", testAuthService_Register_EmailUniqueness)
	t.Run("Invalid Email", testAuthService_Register_InvalidEmail)
	t.Run("Invalid Date Of Birth", testAuthService_Register_InvalidDateOfBirth)
}

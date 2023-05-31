package model

import (
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
)

func newUser() *User {
	return &User{
		Email:             "test@example.com",
		VerificationToken: "token",
		PasswordHash:      "hash",
		PasswordSalt:      "salt",
		FirstName:         "Test",
		LastName:          "User",
		DateOfBirth:       time.Now(),
		RegistrationDate:  time.Now(),
		LastLoginDate:     time.Now(),
		AccountStatus:     AccountStatusVerified,
	}
}

func testValidateValidUser_Valid(t *testing.T) {
	// Valid user
	user := newUser()
	err := ValidateUser(user)
	assert.Nil(t, err)
}

func testValidateUser_MissingVerificationToken(t *testing.T) {
	user := newUser()
	user.VerificationToken = ""
	err := ValidateUser(user)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "VerificationToken")
	errors := err.(validator.ValidationErrors)
	assert.Len(t, errors, 1)
}

func testValidate_ValidUserWithNoLoginDate(t *testing.T) {
	// Valid user
	user := &User{
		Email:             "test@example.com",
		VerificationToken: "token",
		PasswordHash:      "hash",
		PasswordSalt:      "salt",
		FirstName:         "Test",
		LastName:          "User",
		DateOfBirth:       time.Now(),
		RegistrationDate:  time.Now(),
		AccountStatus:     AccountStatusVerified,
	}
	err := ValidateUser(user)
	assert.Nil(t, err)
}

func testValidateUser_InvalidEmail(t *testing.T) {
	user := newUser()
	user.Email = "test-example.com"
	resultError := ValidateUser(user)
	assert.NotNil(t, resultError)
	assert.Contains(t, resultError.Error(), "Email")
	errors := resultError.(validator.ValidationErrors)
	assert.Len(t, errors, 1)
}

func testValidateUser_InvalidUserNames(t *testing.T) {
	user := newUser()
	user.FirstName = "F"
	user.LastName = "L"
	err := ValidateUser(user)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "FirstName")
	assert.Contains(t, err.Error(), "LastName")
	errors := err.(validator.ValidationErrors)
	assert.Len(t, errors, 2)
}

func testValidateUser_MissingBirthDate(t *testing.T) {
	user := &User{
		Email:             "test@example.com",
		VerificationToken: "token",
		PasswordHash:      "hash",
		PasswordSalt:      "salt",
		FirstName:         "Test",
		LastName:          "User",
		LastLoginDate:     time.Now(),
		AccountStatus:     AccountStatusVerified,
	}
	err := ValidateUser(user)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "DateOfBirth")
	assert.Contains(t, err.Error(), "RegistrationDate")
	errors := err.(validator.ValidationErrors)
	assert.Len(t, errors, 2)
}

func testValidateUser_BirthDateInFuture(t *testing.T) {
	user := newUser()
	user.DateOfBirth = time.Now().Add(24 * time.Hour)
	resultError := ValidateUser(user)
	assert.NotNil(t, resultError)
	assert.Contains(t, resultError.Error(), "DateOfBirth")
	errors := resultError.(validator.ValidationErrors)
	assert.Len(t, errors, 1)
}

func TestValidateUser(t *testing.T) {
	t.Run("Valid User", testValidateValidUser_Valid)
	t.Run("User without verification token", testValidateUser_MissingVerificationToken)
	t.Run("Valid User With No Login Date", testValidate_ValidUserWithNoLoginDate)
	t.Run("Invalid Email", testValidateUser_InvalidEmail)
	t.Run("Invalid User Names", testValidateUser_InvalidUserNames)
	t.Run("Missing Birth Date", testValidateUser_MissingBirthDate)
	t.Run("Birth Date In Future", testValidateUser_BirthDateInFuture)
}

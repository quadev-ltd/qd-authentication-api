package model

import (
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func testValidateValidUser(t *testing.T) {
	// Valid user
	user := &User{
		ID:               uuid.New(),
		Email:            "test@example.com",
		PasswordHash:     "hash",
		PasswordSalt:     "salt",
		FirstName:        "Test",
		LastName:         "User",
		DateOfBirth:      time.Now(),
		RegistrationDate: time.Now(),
		LastLoginDate:    time.Now(),
		AccountStatus:    AccountStatusActive,
	}
	err := ValidateUser(user)
	assert.Nil(t, err)
}

func testValidateValidUserWithNoLoginDate(t *testing.T) {
	// Valid user
	user := &User{
		ID:               uuid.New(),
		Email:            "test@example.com",
		PasswordHash:     "hash",
		PasswordSalt:     "salt",
		FirstName:        "Test",
		LastName:         "User",
		DateOfBirth:      time.Now(),
		RegistrationDate: time.Now(),
		AccountStatus:    AccountStatusActive,
	}
	err := ValidateUser(user)
	assert.Nil(t, err)
}

func testValidateUserMissingID(t *testing.T) {
	user := &User{
		Email:            "test@example.com",
		PasswordHash:     "hash",
		PasswordSalt:     "salt",
		FirstName:        "Test",
		LastName:         "User",
		DateOfBirth:      time.Now(),
		RegistrationDate: time.Now(),
		LastLoginDate:    time.Now(),
		AccountStatus:    AccountStatusActive,
	}
	err := ValidateUser(user)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "ID")
	errors := err.(validator.ValidationErrors)
	assert.Len(t, errors, 1)
}

func testValidateUserInvalidEmail(t *testing.T) {
	user := &User{
		ID:               uuid.New(),
		Email:            "test-example.com",
		PasswordHash:     "hash",
		PasswordSalt:     "salt",
		FirstName:        "Test",
		LastName:         "User",
		DateOfBirth:      time.Now(),
		RegistrationDate: time.Now(),
		LastLoginDate:    time.Now(),
		AccountStatus:    AccountStatusActive,
	}
	err := ValidateUser(user)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Email")
	errors := err.(validator.ValidationErrors)
	assert.Len(t, errors, 1)
}

func testValidateUserInvalidUserNames(t *testing.T) {
	user := &User{
		ID:               uuid.New(),
		Email:            "test@example.com",
		PasswordHash:     "hash",
		PasswordSalt:     "salt",
		FirstName:        "T",
		LastName:         "U",
		DateOfBirth:      time.Now(),
		RegistrationDate: time.Now(),
		LastLoginDate:    time.Now(),
		AccountStatus:    AccountStatusActive,
	}
	err := ValidateUser(user)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "FirstName")
	assert.Contains(t, err.Error(), "LastName")
	errors := err.(validator.ValidationErrors)
	assert.Len(t, errors, 2)
}

func testValidateUserMissingBirthDate(t *testing.T) {
	user := &User{
		ID:            uuid.New(),
		Email:         "test@example.com",
		PasswordHash:  "hash",
		PasswordSalt:  "salt",
		FirstName:     "Test",
		LastName:      "User",
		LastLoginDate: time.Now(),
		AccountStatus: AccountStatusActive,
	}
	err := ValidateUser(user)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "DateOfBirth")
	assert.Contains(t, err.Error(), "RegistrationDate")
	errors := err.(validator.ValidationErrors)
	assert.Len(t, errors, 2)
}

func testValidateUserBirthDateInFuture(t *testing.T) {
	user := &User{
		ID:               uuid.New(),
		Email:            "test@example.com",
		PasswordHash:     "hash",
		PasswordSalt:     "salt",
		FirstName:        "Test",
		LastName:         "User",
		DateOfBirth:      time.Now().Add(24 * time.Hour), // This is one day in the future
		RegistrationDate: time.Now(),
		LastLoginDate:    time.Now(),
		AccountStatus:    AccountStatusActive,
	}
	err := ValidateUser(user)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "DateOfBirth")
	errors := err.(validator.ValidationErrors)
	assert.Len(t, errors, 1)
}

func TestValidateUser(t *testing.T) {
	t.Run("Valid User", testValidateValidUser)
	t.Run("Valid User With No Login Date", testValidateValidUserWithNoLoginDate)
	t.Run("Missing ID", testValidateUserMissingID)
	t.Run("Invalid Email", testValidateUserInvalidEmail)
	t.Run("Invalid User Names", testValidateUserInvalidUserNames)
	t.Run("Missing Birth Date", testValidateUserMissingBirthDate)
	t.Run("Birth Date In Future", testValidateUserBirthDateInFuture)
}

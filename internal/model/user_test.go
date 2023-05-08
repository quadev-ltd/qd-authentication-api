package model

import (
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestValidateValidUser(test *testing.T) {
	// Valid user
	user := &User{
		ID:               uuid.New(),
		Email:            "test@example.com",
		Username:         "testuser",
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

func TestValidateValidUserWithNoLoginDate(test *testing.T) {
	// Valid user
	user := &User{
		ID:               uuid.New(),
		Email:            "test@example.com",
		Username:         "testuser",
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

func TestValidateUserMissingID(test *testing.T) {
	user := &User{
		Email:            "test@example.com",
		Username:         "testuser",
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

func TestValidateUserInvalidEmail(test *testing.T) {
	user := &User{
		ID:               uuid.New(),
		Email:            "test-example.com",
		Username:         "testuser",
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

func TestValidateUserInvalidUserNames(test *testing.T) {
	user := &User{
		ID:               uuid.New(),
		Email:            "test@example.com",
		Username:         "t",
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
	assert.Contains(t, err.Error(), "Username")
	assert.Contains(t, err.Error(), "FirstName")
	assert.Contains(t, err.Error(), "LastName")
	errors := err.(validator.ValidationErrors)
	assert.Len(t, errors, 3)
}

func TestValidateUserMissingBirthDate(test *testing.T) {
	user := &User{
		ID:            uuid.New(),
		Email:         "test@example.com",
		Username:      "testuser",
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

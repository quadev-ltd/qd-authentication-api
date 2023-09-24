package model

import (
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
)

func newUser() *User {
	return &User{
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
		AccountStatus:               AccountStatusVerified,
	}
}

func TestValidateUser(t *testing.T) {
	t.Run("Valid User", func(t *testing.T) {
		// Valid user
		user := newUser()
		err := ValidateUser(user)
		assert.Nil(t, err)
	})
	t.Run("User without verification token", func(t *testing.T) {
		user := newUser()
		user.VerificationToken = ""
		err := ValidateUser(user)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "VerificationToken")
		errors := err.(validator.ValidationErrors)
		assert.Len(t, errors, 1)
	})
	t.Run("Valid User With No Login Date", func(t *testing.T) {
		// Valid user
		user := newUser()
		user.LastLoginDate = time.Time{}
		err := ValidateUser(user)
		assert.Nil(t, err)
	})
	t.Run("Invalid Email", func(t *testing.T) {
		user := newUser()
		user.Email = "test-example.com"
		resultError := ValidateUser(user)
		assert.NotNil(t, resultError)
		assert.Contains(t, resultError.Error(), "Email")
		errors := resultError.(validator.ValidationErrors)
		assert.Len(t, errors, 1)
	})
	t.Run("Invalid User Names", func(t *testing.T) {
		user := newUser()
		user.FirstName = "F"
		user.LastName = "L"
		err := ValidateUser(user)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "FirstName")
		assert.Contains(t, err.Error(), "LastName")
		errors := err.(validator.ValidationErrors)
		assert.Len(t, errors, 2)
	})
	t.Run("Missing Birth Date", func(t *testing.T) {
		user := newUser()
		user.DateOfBirth = time.Time{}
		user.RegistrationDate = time.Time{}
		err := ValidateUser(user)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "DateOfBirth")
		assert.Contains(t, err.Error(), "RegistrationDate")
		errors := err.(validator.ValidationErrors)
		assert.Len(t, errors, 2)
	})
	t.Run("Missing Token Verifiction Token Expiry Date", func(t *testing.T) {
		user := newUser()
		user.VerificationTokenExpiryDate = time.Time{}
		err := ValidateUser(user)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "VerificationTokenExpiryDate")
		errors := err.(validator.ValidationErrors)
		assert.Len(t, errors, 1)
	})
	t.Run("Birth Date In Future", func(t *testing.T) {
		user := newUser()
		user.DateOfBirth = time.Now().Add(24 * time.Hour)
		resultError := ValidateUser(user)
		assert.NotNil(t, resultError)
		assert.Contains(t, resultError.Error(), "DateOfBirth")
		errors := resultError.(validator.ValidationErrors)
		assert.Len(t, errors, 1)
	})
}

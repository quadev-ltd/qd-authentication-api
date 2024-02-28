package model

import (
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func newUser() *User {
	return &User{
		Email:            "test@example.com",
		PasswordHash:     "hash",
		PasswordSalt:     "salt",
		FirstName:        "Test",
		LastName:         "User",
		DateOfBirth:      time.Now(),
		RegistrationDate: time.Now(),
		LastLoginDate:    time.Now(),
		AccountStatus:    AccountStatusVerified,
	}
}

func TestValidateUser(t *testing.T) {
	t.Run("Valid_User", func(t *testing.T) {
		// Valid user
		user := newUser()
		err := ValidateUser(user)
		assert.Nil(t, err)
	})
	t.Run("Valid_User_With_No_Login_Date", func(t *testing.T) {
		// Valid user
		user := newUser()
		user.LastLoginDate = time.Time{}
		err := ValidateUser(user)
		assert.Nil(t, err)
	})
	t.Run("Invalid_Email", func(t *testing.T) {
		user := newUser()
		user.Email = "test-example.com"
		resultError := ValidateUser(user)
		assert.NotNil(t, resultError)
		assert.Contains(t, resultError.Error(), "Email")
		errors := resultError.(validator.ValidationErrors)
		assert.Len(t, errors, 1)
	})
	t.Run("Invalid_User_Names", func(t *testing.T) {
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
	t.Run("Missing_Birth_Date", func(t *testing.T) {
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
	t.Run("Birth_Date_In_Future", func(t *testing.T) {
		user := newUser()
		user.DateOfBirth = time.Now().Add(24 * time.Hour)
		resultError := ValidateUser(user)
		assert.NotNil(t, resultError)
		assert.Contains(t, resultError.Error(), "DateOfBirth")
		errors := resultError.(validator.ValidationErrors)
		assert.Len(t, errors, 1)
	})
}

type PasswordValidationTestSuite struct {
	suite.Suite
}

type TestCase struct {
	name     string
	password string
	result   bool
}

func (suite *PasswordValidationTestSuite) UseCaseTable() {
	testCases := []TestCase{
		{
			name:     "Valid_Password",
			password: "Test1234!",
			result:   true,
		},
		{
			name:     "No_Number",
			password: "Test!",
			result:   true,
		},
		{
			name:     "No_Upcase",
			password: "test1234!",
			result:   true,
		},
		{
			name:     "No_Lowcase",
			password: "TEST1234!",
			result:   true,
		},
		{
			name:     "No_Symbol",
			password: "Test1234",
			result:   true,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			isPasswordComplex := IsPasswordComplex(tc.password)
			assert.Equal(suite.T(), tc.result, isPasswordComplex)
		})
	}
}

func TestPasswordValidation(t *testing.T) {
	suite.Run(t, new(PasswordValidationTestSuite))
}

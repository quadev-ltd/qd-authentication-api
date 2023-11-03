package model

import (
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
)

// AccountStatus is the type for the account status
type AccountStatus int

// User is the model for the user
type User struct {
	Email                       string        `validate:"required,email"`
	VerificationToken           string        `validate:"required"`
	VerificationTokenExpiryDate time.Time     `validate:"required"`
	PasswordHash                string        `validate:"required"`
	PasswordSalt                string        `validate:"required"`
	FirstName                   string        `validate:"required,min=2,max=30"`
	LastName                    string        `validate:"required,min=2,max=30"`
	DateOfBirth                 time.Time     `validate:"required,not_future"`
	RegistrationDate            time.Time     `validate:"required"`
	LastLoginDate               time.Time     `validate:"omitempty"`
	AccountStatus               AccountStatus `validate:"required"`
}

// AccountStatus constants
const (
	AccountStatusUnverified AccountStatus = 1
	AccountStatusVerified   AccountStatus = 2
)

// ValidateUser validates the userproperties
func ValidateUser(user *User) error {
	validate := validator.New()
	validate.RegisterValidation("not_future", func(fl validator.FieldLevel) bool {
		asTime, ok := fl.Field().Interface().(time.Time)
		if !ok {
			return false // it's not even a time.Time
		}
		// it's valid if the time is not after Now
		return !asTime.After(time.Now())
	})
	error := validate.Struct(user)
	if error != nil {
		return error
	}
	return nil
}

// EmailInUseError is a Custom email error type
type EmailInUseError struct {
	Email string
}

// Error returns the error message
func (e *EmailInUseError) Error() string {
	return fmt.Sprintf("Email %s is already in use", e.Email)
}

// WrongEmailOrPassword is a Custom wrong email or password error type
type WrongEmailOrPassword struct {
	FieldName string
}

// Error returns the error message
func (e *WrongEmailOrPassword) Error() string {
	return fmt.Sprintf("Wrong %s", e.FieldName)
}

package model

import (
	"fmt"
	"time"
	"unicode"

	"github.com/go-playground/validator/v10"
	"github.com/quadev-ltd/qd-common/pb/gen/go/pb_errors"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// AccountStatus is the type for the account status
type AccountStatus int

// User is the model for the user
type User struct {
	ID               primitive.ObjectID `bson:"_id,omitempty"`
	Email            string             `bson:"email" validate:"required,email"`
	PasswordHash     string             `bson:"password_hash" validate:"required"`
	PasswordSalt     string             `bson:"password_salt" validate:"required"`
	FirstName        string             `bson:"first_name" validate:"required,max=30"`
	LastName         string             `bson:"last_name" validate:"required,max=30"`
	DateOfBirth      time.Time          `bson:"date_of_birth" validate:"required,not_future"`
	RegistrationDate time.Time          `bson:"registration_date" validate:"required"`
	LastLoginDate    time.Time          `bson:"last_login_date" validate:"omitempty"`
	AccountStatus    AccountStatus      `bson:"account_status" validate:"required"`
}

// AccountStatus constants
const (
	AccountStatusUnverified AccountStatus = 1
	AccountStatusVerified   AccountStatus = 2
)

// ValidateUser validates the userproperties
func ValidateUser(user *User) error {
	validate := validator.New()
	// Registering a custom validation for date of birth
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

// ValidatePartialUser validates the user properties
func ValidatePartialUser(user *User, fields ...string) error {
	validate := validator.New()
	validate.RegisterValidation("not_future", func(fl validator.FieldLevel) bool {
		asTime, ok := fl.Field().Interface().(time.Time)
		if !ok {
			return false
		}
		return !asTime.After(time.Now())
	})
	error := validate.StructPartial(user, fields...)
	if error != nil {
		return error
	}
	return nil
}

// ParseValidationError parses the validation error
func ParseValidationError(validationError error) ([]*pb_errors.FieldError, error) {
	if validationError != nil {
		// Check if the errors are of type validator.ValidationErrors
		if validationError, ok := validationError.(validator.ValidationErrors); ok {
			var errors []*pb_errors.FieldError
			for _, valErr := range validationError {
				fieldError := &pb_errors.FieldError{
					Field: valErr.Field(),
					Error: valErr.Tag(),
				}
				errors = append(errors, fieldError)
			}
			return errors, nil
		}
		return nil, validationError
	}
	return nil, nil
}

// IsPasswordComplex checks if the password meets complexity requirements
func IsPasswordComplex(password string) bool {
	var (
		hasMinLen      = false
		hasUpper       = false
		hasLower       = false
		hasNumber      = false
		hasSpecialChar = false
	)

	const minLen = 8
	if len(password) >= minLen {
		hasMinLen = true
	}

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecialChar = true
		}
	}

	return hasMinLen && hasUpper && hasLower && hasNumber && hasSpecialChar
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

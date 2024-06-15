package model

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/go-playground/validator/v10"
	"github.com/quadev-ltd/qd-common/pb/gen/go/pb_errors"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// AccountStatus is an int
type AccountStatus int

// AuthenticationType is a string
type AuthenticationType string

// Authentication possible types
const (
	PasswordAuthType = "PASSWORD"
	FirebaseAuthType = "FIREBASE"
)

// User is the model for the user
type User struct {
	ID               primitive.ObjectID   `bson:"_id,omitempty"`
	Email            string               `bson:"email" validate:"required,email,lowercase"`
	PasswordHash     string               `bson:"passwordHash" validate:"required_password"`
	PasswordSalt     string               `bson:"passwordSalt" validate:"required_password"`
	FirstName        string               `bson:"firstName" validate:"required,max=30"`
	LastName         string               `bson:"lastName" validate:"required,max=30"`
	DateOfBirth      time.Time            `bson:"dateOfBirth" validate:"not_future"`
	RegistrationDate time.Time            `bson:"registrationDate" validate:"required"`
	LastLoginDate    time.Time            `bson:"lastLoginDate" validate:"omitempty"`
	AccountStatus    AccountStatus        `bson:"accountStatus" validate:"required"`
	AuthTypes        []AuthenticationType `bson:"authTypes" validate:"required"`
}

// AccountStatus constants
const (
	AccountStatusUnverified AccountStatus = 1
	AccountStatusVerified   AccountStatus = 2
)

// ContainsAuthType checks if array of types contains the given type
func ContainsAuthType(types []AuthenticationType, authType AuthenticationType) bool {
	for _, t := range types {
		if t == authType {
			return true
		}
	}
	return false
}

func passwordRequiredIfUsingPasswordAuth(fl validator.FieldLevel) bool {
	user, ok := fl.Parent().Interface().(User)
	if !ok {
		return false
	}
	usesPasswordAuth := ContainsAuthType(user.AuthTypes, PasswordAuthType)
	if usesPasswordAuth {
		field := fl.Field().String() // Get the value of the field being validated
		return field != ""           // The field must not be empty
	}
	// If PasswordAuthType is not used, then the password is not required
	return true
}

func notFuture(fl validator.FieldLevel) bool {
	asTime, ok := fl.Field().Interface().(time.Time)
	if !ok {
		return false
	}
	if asTime.IsZero() {
		return true
	}
	return !asTime.After(time.Now())
}

func getValidator() *validator.Validate {
	validate := validator.New()
	validate.RegisterValidation("required_password", passwordRequiredIfUsingPasswordAuth)
	validate.RegisterValidation("not_future", notFuture)
	validate.RegisterValidation("lowercase", func(fl validator.FieldLevel) bool {
		return strings.ToLower(fl.Field().String()) == fl.Field().String()
	})
	return validate
}

// ValidateUser validates the userproperties
func ValidateUser(user *User) error {
	validate := getValidator()
	error := validate.Struct(user)
	if error != nil {
		return error
	}
	return nil
}

// ValidatePartialUser validates the user properties
func ValidatePartialUser(user *User, fields ...string) error {
	validate := getValidator()

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

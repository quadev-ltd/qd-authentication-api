package model

import (
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type AccountStatus int

type User struct {
	ID               uuid.UUID     `validate:"required"`
	Email            string        `validate:"required,email"`
	PasswordHash     string        `validate:"required"`
	PasswordSalt     string        `validate:"required"`
	FirstName        string        `validate:"required,min=2,max=30"`
	LastName         string        `validate:"required,min=2,max=30"`
	DateOfBirth      time.Time     `validate:"required"`
	RegistrationDate time.Time     `validate:"required"`
	LastLoginDate    time.Time     `validate:"omitempty"`
	AccountStatus    AccountStatus `validate:"required"`
}

const (
	AccountStatusActive   AccountStatus = 1
	AccountStatusDisabled AccountStatus = 2
	AccountStatusDeleted  AccountStatus = 3
)

func ValidateUser(user *User) error {
	validate := validator.New()
	err := validate.Struct(user)
	if err != nil {
		return err
	}
	return nil
}

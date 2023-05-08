package model

import (
	"time"
)

type User struct {
	ID               string `validate:"required,uuid"`
	Email            string `validate:"required,email"`
	Username         string
	PasswordHash     string `validate:"required,len=64"`
	PasswordSalt     string
	FirstName        string
	LastName         string
	DateOfBirth      time.Time
	RegistrationDate time.Time
	LastLoginDate    time.Time
	AccountStatus    int
}

// AccountStatus values
const (
	AccountStatusActive   = 1
	AccountStatusDisabled = 2
	AccountStatusDeleted  = 3
)

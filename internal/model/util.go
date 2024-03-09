package model

import (
	"time"

	commonToken "github.com/quadev-ltd/qd-common/pkg/token"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// NewToken creates a new token
func NewToken(token string) *Token {
	return &Token{
		UserID:    primitive.NewObjectID(),
		Token:     token,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(2 * time.Hour),
		Type:      commonToken.EmailVerificationTokenType,
		Revoked:   false,
	}
}

// NewUser creates a new user
func NewUser() *User {
	return &User{
		Email:            "test@example.com",
		PasswordHash:     "hash",
		PasswordSalt:     "salt",
		FirstName:        "Test",
		LastName:         "User",
		DateOfBirth:      time.Now(),
		RegistrationDate: time.Now(),
		LastLoginDate:    time.Now(),
		AccountStatus:    AccountStatusUnverified,
	}
}

package model

import (
	"time"

	jwtCommon "github.com/quadev-ltd/qd-common/pkg/jwt"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// NewToken creates a new token
func NewToken(token string) *Token {
	return &Token{
		UserID:    primitive.NewObjectID(),
		Token:     token,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(2 * time.Hour),
		Type:      jwtCommon.EmailVerificationTokenType,
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

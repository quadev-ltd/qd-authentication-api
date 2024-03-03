package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

func NewToken(token string) *Token {
	return &Token{
		UserID:    primitive.NewObjectID(),
		Token:     token,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(2 * time.Hour),
		Type:      EmailVerificationTokenType,
		Revoked:   false,
	}
}

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

package model

import (
	"time"

	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// TokenType is the type for the token type
type TokenType string

// Token types
const (
	EmailVerificationTokenType TokenType = "EmailVerificationTokenType"
	ResetPasswordTokenType     TokenType = "ResetPasswordTokenType"
	RefreshTokenType           TokenType = "RefreshTokenType"
)

// Token is the model for the refresh token
type Token struct {
	Token     string             `bson:"token"`
	IssuedAt  time.Time          `bson:"issuedAt"`
	ExpiresAt time.Time          `bson:"expiresAt"`
	Revoked   bool               `bson:"revoked"`
	Type      TokenType          `bson:"type"`
	UserID    primitive.ObjectID `bson:"userId"` // Reference to User
}

// ValidateUser validates the userproperties
func ValidateToken(user *Token) error {
	validate := validator.New()
	error := validate.Struct(user)
	if error != nil {
		return error
	}
	return nil
}

package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// TokenType is the type for the token type
type TokenType string

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

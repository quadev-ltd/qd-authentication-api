package model

import (
	"time"

	"github.com/go-playground/validator/v10"
	commonToken "github.com/quadev-ltd/qd-common/pkg/token"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Token is the model for the refresh token
type Token struct {
	TokenHash string                `bson:"token_hash"`
	Salt      string                `bson:"salt"`
	IssuedAt  time.Time             `bson:"issued_at"`
	ExpiresAt time.Time             `bson:"expires_at"`
	Revoked   bool                  `bson:"revoked"`
	Type      commonToken.TokenType `bson:"type"`
	UserID    primitive.ObjectID    `bson:"user_id"` // Reference to User
}

// ValidateToken validates the userproperties
func ValidateToken(user *Token) error {
	validate := validator.New()
	error := validate.Struct(user)
	if error != nil {
		return error
	}
	return nil
}

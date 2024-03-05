package model

import (
	"time"

	"github.com/go-playground/validator/v10"
	commonJWT "github.com/quadev-ltd/qd-common/pkg/jwt"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Token is the model for the refresh token
type Token struct {
	Token     string              `bson:"token"`
	IssuedAt  time.Time           `bson:"issuedAt"`
	ExpiresAt time.Time           `bson:"expiresAt"`
	Revoked   bool                `bson:"revoked"`
	Type      commonJWT.TokenType `bson:"type"`
	UserID    primitive.ObjectID  `bson:"userId"` // Reference to User
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

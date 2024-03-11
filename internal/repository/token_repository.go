package repository

import (
	"context"

	commonToken "github.com/quadev-ltd/qd-common/pkg/token"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"qd-authentication-api/internal/model"
)

// TokenRepositoryer is the interface for the token repository
type TokenRepositoryer interface {
	InsertToken(ctx context.Context, token *model.Token) (interface{}, error)
	GetByToken(ctx context.Context, token string) (*model.Token, error)
	GetByUserIDAndTokenType(ctx context.Context, userID primitive.ObjectID, tokenType commonToken.TokenType) (*model.Token, error)
	Update(ctx context.Context, token *model.Token) error
	Remove(ctx context.Context, token *model.Token) error
}

package repository

import (
	"context"

	"qd-authentication-api/internal/model"
)

// TokenRepositoryer is the interface for the token repository
type TokenRepositoryer interface {
	Create(ctx context.Context, token *model.Token) error
	GetByToken(ctx context.Context, token string) (*model.Token, error)
	Update(ctx context.Context, token *model.Token) error
	Remove(ctx context.Context, token string) error
}

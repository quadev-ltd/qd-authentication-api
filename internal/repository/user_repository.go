package repository

import (
	"context"
	"qd-authentication-api/internal/model"
)

// UserRepositoryer is the interface for the user repository
type UserRepositoryer interface {
	Create(ctx context.Context, user *model.User) error
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	GetByVerificationToken(ctx context.Context, token string) (*model.User, error)
	Update(ctx context.Context, user *model.User) error
}

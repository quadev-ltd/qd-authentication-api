package repository

import (
	"context"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"qd-authentication-api/internal/model"
)

// UserRepositoryer is the interface for the user repository
type UserRepositoryer interface {
	Create(ctx context.Context, user *model.User) (interface{}, error)
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	GetByUserId(ctx context.Context, userId primitive.ObjectID) (*model.User, error)
	Update(ctx context.Context, user *model.User) error
}

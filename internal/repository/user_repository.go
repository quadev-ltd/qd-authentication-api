package repository

import (
	"context"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"qd-authentication-api/internal/model"
)

// UserRepositoryer is the interface for the user repository
type UserRepositoryer interface {
	InsertUser(ctx context.Context, user *model.User) (interface{}, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	GetByUserID(ctx context.Context, userID primitive.ObjectID) (*model.User, error)
	UpdateStatus(ctx context.Context, user *model.User) error
	UpdatePassword(ctx context.Context, user *model.User) error
	UpdateProfileDetails(ctx context.Context, user *model.User) error
}

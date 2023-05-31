package repository

import (
	"qd_authentication_api/internal/model"
)

type UserRepository interface {
	Create(user *model.User) error
	GetByEmail(email string) (*model.User, error)
	GetByVerificationToken(token string) (*model.User, error)
	Update(user *model.User) error
}

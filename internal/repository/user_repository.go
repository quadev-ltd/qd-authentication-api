package repository

import (
	"qd_authentication_api/internal/model"
	mongoRepository "qd_authentication_api/internal/repository/mongo"
)

type UserRepositoryer interface {
	Create(user *model.User) error
	GetByEmail(email string) (*model.User, error)
	GetByVerificationToken(token string) (*model.User, error)
	Update(user *model.User) error
}

var _ UserRepositoryer = &mongoRepository.MongoUserRepository{}

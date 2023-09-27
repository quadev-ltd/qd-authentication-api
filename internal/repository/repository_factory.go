package repository

import (
	"context"
	"qd_authentication_api/internal/config"
	mongoRepository "qd_authentication_api/internal/repository/mongo"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type RepositoryFactoryer interface {
	CreateRepository(config *config.Config) (Repositoryer, error)
}

type RepositoryFactory struct{}

func (repositoryFactory *RepositoryFactory) CreateRepository(config *config.Config) (Repositoryer, error) {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(config.DB.URI))
	if err != nil {
		return nil, err
	}

	userRepo := mongoRepository.NewMongoUserRepository(client)

	return &Repository{
		client:         client,
		userRepository: userRepo,
	}, nil
}

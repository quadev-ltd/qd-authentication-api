package mongo

import (
	"context"
	"qd_authentication_api/internal/config"
	"qd_authentication_api/internal/repository"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type RepositoryFactory struct{}

var _ repository.RepositoryFactoryer = &RepositoryFactory{}

func (repositoryFactory *RepositoryFactory) CreateRepository(
	config *config.Config,
) (repository.Repositoryer, error) {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(config.DB.URI))
	if err != nil {
		return nil, err
	}

	userRepository := NewUserRepository(client)

	return &Repository{
		client:         client,
		userRepository: userRepository,
	}, nil
}

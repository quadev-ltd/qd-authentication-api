package mongo

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"qd-authentication-api/internal/config"
	"qd-authentication-api/internal/repository"
)

// RepositoryFactory is the implementation of the repository factory
type RepositoryFactory struct{}

var _ repository.Factoryer = &RepositoryFactory{}

// CreateRepository creates a repository
func (repositoryFactory *RepositoryFactory) CreateRepository(
	config *config.Config,
) (repository.Repositoryer, error) {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(config.AuthenticationDB.URI))
	if err != nil {
		return nil, err
	}

	userRepository := NewUserRepository(client)
	tokenRepository := NewTokenRepository(client)

	return &Repository{
		client:          client,
		userRepository:  userRepository,
		tokenRepository: tokenRepository,
	}, nil
}

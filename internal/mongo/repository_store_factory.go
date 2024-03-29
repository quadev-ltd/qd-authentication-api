package mongo

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"qd-authentication-api/internal/config"
	"qd-authentication-api/internal/repository"
)

// RepositoryStoreFactory is the implementation of the repository factory
type RepositoryStoreFactory struct{}

var _ repository.StoreFactoryer = &RepositoryStoreFactory{}

// CreateRepositoryStore creates a repository
func (repositoryFactory *RepositoryStoreFactory) CreateRepositoryStore(
	config *config.Config,
) (repository.Storer, error) {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(config.AuthenticationDB.URI))
	if err != nil {
		return nil, err
	}

	userRepository := NewUserRepository(client)
	tokenRepository := NewTokenRepository(client)

	return &RepositoryStore{
		client:          client,
		userRepository:  userRepository,
		tokenRepository: tokenRepository,
	}, nil
}

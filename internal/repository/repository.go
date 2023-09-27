package repository

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"
)

type Repositoryer interface {
	GetUserRepository() UserRepositoryer
	Close() error
}

type Repository struct {
	userRepository UserRepositoryer
	client         *mongo.Client
}

func (repository *Repository) GetUserRepository() UserRepositoryer {
	return repository.userRepository
}

func (repository *Repository) Close() error {
	if repository.client != nil {
		return repository.client.Disconnect(context.Background())
	}
	return nil
}

package repository

import (
	"context"
	"errors"
)

type Repositoryer interface {
	GetUserRepository() UserRepositoryer
	Close() error
}

type MongoClienter interface {
	Connect(ctx context.Context) error
	Disconnect(ctx context.Context) error
}

type Repository struct {
	userRepository UserRepositoryer
	client         MongoClienter
}

func (repository *Repository) GetUserRepository() UserRepositoryer {
	return repository.userRepository
}

func (repository *Repository) Close() error {
	if repository.client != nil {
		return repository.client.Disconnect(context.Background())
	}
	return errors.New("Repository client is nil.")
}

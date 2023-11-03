package mongo

import (
	"context"
	"qd_authentication_api/internal/repository"
)

type MongoClienter interface {
	Connect(ctx context.Context) error
	Disconnect(ctx context.Context) error
}

type Repository struct {
	userRepository repository.UserRepositoryer
	client         MongoClienter
}

var _ repository.Repositoryer = &Repository{}

func (mongoRepository *Repository) GetUserRepository() repository.UserRepositoryer {
	return mongoRepository.userRepository
}

func (mongoRepository *Repository) Close() error {
	if mongoRepository.client != nil {
		return mongoRepository.client.Disconnect(context.Background())
	}
	return &repository.RepositoryError{
		Message: "Repository client is nil.",
	}
}

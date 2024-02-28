package mongo

import (
	"context"

	"qd-authentication-api/internal/repository"
)

// Clienter specific client interface
type Clienter interface {
	Connect(ctx context.Context) error
	Disconnect(ctx context.Context) error
}

// RepositoryStore is a mongo specific repository
type RepositoryStore struct {
	userRepository  repository.UserRepositoryer
	tokenRepository repository.TokenRepositoryer
	client          Clienter
}

var _ repository.Storer = &RepositoryStore{}

// GetUserRepository returns the user repository
func (mongoRepository *RepositoryStore) GetUserRepository() repository.UserRepositoryer {
	return mongoRepository.userRepository
}

// GetTokenRepository returns the user repository
func (mongoRepository *RepositoryStore) GetTokenRepository() repository.TokenRepositoryer {
	return mongoRepository.tokenRepository
}

// Close closes the mongo repository
func (mongoRepository *RepositoryStore) Close() error {
	if mongoRepository.client != nil {
		return mongoRepository.client.Disconnect(context.Background())
	}
	return &repository.Error{
		Message: "Repository client is nil",
	}
}

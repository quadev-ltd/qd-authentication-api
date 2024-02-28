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

// Repository is a mongo specific repository
type Repository struct {
	userRepository  repository.UserRepositoryer
	tokenRepository repository.TokenRepositoryer
	client          Clienter
}

var _ repository.Repositoryer = &Repository{}

// GetUserRepository returns the user repository
func (mongoRepository *Repository) GetUserRepository() repository.UserRepositoryer {
	return mongoRepository.userRepository
}

// GetTokenRepository returns the user repository
func (mongoRepository *Repository) GetTokenRepository() repository.TokenRepositoryer {
	return mongoRepository.tokenRepository
}

// Close closes the mongo repository
func (mongoRepository *Repository) Close() error {
	if mongoRepository.client != nil {
		return mongoRepository.client.Disconnect(context.Background())
	}
	return &repository.Error{
		Message: "Repository client is nil",
	}
}

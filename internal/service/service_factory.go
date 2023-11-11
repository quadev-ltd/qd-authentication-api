package service

import (
	"qd-authentication-api/internal/config"
	mongo "qd-authentication-api/internal/mongo"
)

// Factoryer is a factory for creating a service
type Factoryer interface {
	CreateService(config *config.Config) (Servicer, error)
}

// Factory is the implementation of the service factory
type Factory struct{}

var _ Factoryer = &Factory{}

// CreateService creates a service
func (serviceFactory *Factory) CreateService(
	config *config.Config,
) (Servicer, error) {
	repository, err := (&mongo.RepositoryFactory{}).CreateRepository(config)
	if err != nil {
		return nil, err
	}

	emailServiceConfig := EmailServiceConfig{
		AppName:                   config.App,
		EmailVerificationEndpoint: config.EmailVerificationEndpoint,
		GRPCHost:                  config.Email.Host,
		GRPCPort:                  config.Email.Port,
	}
	emailService := NewEmailService(emailServiceConfig, &SMTPService{})
	jwtAuthenticator, err := NewJWTAuthenticator("./keys")
	if err != nil {
		return nil, err
	}
	authenticationService := NewAuthenticationService(
		emailService,
		repository.GetUserRepository(),
		jwtAuthenticator,
	)

	return &Service{
		authenticationService: authenticationService,
		repository:            repository,
	}, nil
}

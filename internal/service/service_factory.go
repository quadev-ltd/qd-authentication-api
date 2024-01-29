package service

import (
	"fmt"

	"github.com/rs/zerolog/log"

	"qd-authentication-api/internal/config"
	"qd-authentication-api/internal/jwt"
	mongo "qd-authentication-api/internal/mongo"
)

// Factoryer is a factory for creating a service
type Factoryer interface {
	CreateService(*config.Config) (Servicer, error)
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
		log.Error().Msg(fmt.Sprintf(
			"Failed to create repository. connectionrstring: %s environment: %s",
			config.AuthenticationDB.URI,
			config.Environment,
		))
		return nil, err
	}

	emailServiceConfig := EmailServiceConfig{
		AppName:                   config.App,
		EmailVerificationEndpoint: config.EmailVerificationEndpoint,
		GRPCHost:                  config.Email.Host,
		GRPCPort:                  config.Email.Port,
		TLSEnabled:                config.TLSEnabled,
	}
	emailService := NewEmailService(emailServiceConfig)
	jwtAuthenticator, err := jwt.NewJWTSigner("./keys")
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

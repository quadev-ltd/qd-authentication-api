package service

import (
	"fmt"

	commonConfig "github.com/quadev-ltd/qd-common/pkg/config"
	"github.com/rs/zerolog/log"

	"qd-authentication-api/internal/config"
	"qd-authentication-api/internal/jwt"
	mongo "qd-authentication-api/internal/mongo"
)

// Factoryer is a factory for creating a service
type Factoryer interface {
	CreateService(*config.Config, *commonConfig.Config) (Servicer, error)
}

// Factory is the implementation of the service factory
type Factory struct{}

var _ Factoryer = &Factory{}

// CreateService creates a service
func (serviceFactory *Factory) CreateService(
	config *config.Config,
	centralConfig *commonConfig.Config,
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
		EmailVerificationEndpoint: centralConfig.EmailVerificationEndpoint,
		GRPCHost:                  centralConfig.EmailService.Host,
		GRPCPort:                  centralConfig.EmailService.Port,
		TLSEnabled:                centralConfig.TLSEnabled,
	}
	emailService := NewEmailService(emailServiceConfig)
	jwtAuthenticator, err := jwt.NewSigner("./keys")
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

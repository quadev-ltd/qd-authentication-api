package service

import (
	"fmt"

	commonConfig "github.com/quadev-ltd/qd-common/pkg/config"
	"github.com/rs/zerolog/log"

	"qd-authentication-api/internal/config"
	"qd-authentication-api/internal/firebase"
	"qd-authentication-api/internal/jwt"
	mongo "qd-authentication-api/internal/mongo"
	"qd-authentication-api/internal/util"
)

// Factoryer is a factory for creating a service
type Factoryer interface {
	CreateServiceManager(
		*config.Config,
		*commonConfig.Config,
		firebase.AuthServicer,
	) (Managerer, error)
}

// Factory is the implementation of the service factory
type Factory struct{}

var _ Factoryer = &Factory{}

// CreateServiceManager creates a service
func (serviceFactory *Factory) CreateServiceManager(
	config *config.Config,
	centralConfig *commonConfig.Config,
	firebaseService firebase.AuthServicer,
) (Managerer, error) {
	repository, err := (&mongo.RepositoryStoreFactory{}).CreateRepositoryStore(config)
	if err != nil {
		log.Error().Msg(fmt.Sprintf(
			"Failed to create repository. connectionrstring: %s environment: %s",
			config.AuthenticationDB.URI,
			config.Environment,
		))
		return nil, err
	}

	emailServiceConfig := EmailServiceConfig{
		AppName:                   centralConfig.AppName,
		EmailVerificationEndpoint: centralConfig.EmailVerificationEndpoint,
		GRPCHost:                  centralConfig.EmailService.Host,
		GRPCPort:                  centralConfig.EmailService.Port,
		TLSEnabled:                centralConfig.TLSEnabled,
	}
	emailService, err := NewEmailService(emailServiceConfig)
	if err != nil {
		log.Error().Msg("Failed to create email service")
		return nil, err
	}
	jwtManager, err := jwt.NewManager("./keys")
	if err != nil {
		return nil, err
	}

	var firebaseAuthService firebase.AuthServicer
	if firebaseService != nil {
		firebaseAuthService = firebaseService
	} else {
		firebaseAuthService, err = firebase.NewAuthService(config.Firebase.ConfigPath)
		if err != nil {
			log.Error().Msg("Failed to create firebase auth service")
			return nil, err
		}
	}

	userService := NewUserService(
		emailService,
		firebaseAuthService,
		repository.GetUserRepository(),
	)
	timeProvider := &util.RealTimeProvider{}
	tokenService := NewTokenService(
		repository.GetTokenRepository(),
		jwtManager,
		*timeProvider,
		firebaseAuthService,
	)
	passwordService := NewPasswordService(
		emailService,
		tokenService,
		repository.GetUserRepository(),
	)

	return &Manager{
		userService,
		firebaseAuthService,
		tokenService,
		passwordService,
		emailService,
		repository,
	}, nil
}

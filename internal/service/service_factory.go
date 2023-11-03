package service

import (
	"fmt"
	"qd_authentication_api/internal/config"
	mongo "qd_authentication_api/internal/mongo"
)

type ServiceFactoryer interface {
	CreateService(config *config.Config) (Servicer, error)
}

type ServiceFactory struct{}

var _ ServiceFactoryer = &ServiceFactory{}

func (serviceFactory *ServiceFactory) CreateService(
	config *config.Config,
) (Servicer, error) {
	repository, err := (&mongo.RepositoryFactory{}).CreateRepository(config)
	if err != nil {
		return nil, err
	}

	baseUrl := fmt.Sprintf("http://%s:%s", config.REST.Host, config.REST.Port)
	emailServiceConfig := EmailServiceConfig{
		AppName:  config.App,
		BaseUrl:  baseUrl,
		From:     config.SMTP.Username,
		Password: config.SMTP.Password,
		Host:     config.SMTP.Host,
		Port:     config.SMTP.Port,
	}
	emailService := NewEmailService(emailServiceConfig, &SmtpService{})
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

package service

import (
	"fmt"
	"qd_authentication_api/internal/config"
	mongoRepository "qd_authentication_api/internal/repository"
)

type ServiceFactoryer interface {
	CreateService(config *config.Config) (Servicer, error)
}

type ServiceFactory struct{}

var _ ServiceFactoryer = &ServiceFactory{}

func (serviceFactory *ServiceFactory) CreateService(
	config *config.Config,
) (Servicer, error) {
	repository, err := (&mongoRepository.RepositoryFactory{}).CreateRepository(config)
	if err != nil {
		return nil, err
	}

	baseUrl := fmt.Sprintf("%s://%s:%s", config.App.Protocol, config.REST.Host, config.REST.Port)
	emailServiceConfig := EmailServiceConfig{
		AppName:  config.App.Name,
		BaseUrl:  baseUrl,
		From:     config.SMTP.Username,
		Password: config.SMTP.Password,
		Host:     config.SMTP.Host,
		Port:     config.SMTP.Port,
	}
	emailService := NewEmailService(emailServiceConfig, &SmtpService{})
	authenticationService := NewAuthenticationService(
		emailService,
		repository.GetUserRepository(),
		config.Authentication.Key,
	)

	return &Service{
		authenticationService: authenticationService,
		repository:            repository,
	}, nil
}

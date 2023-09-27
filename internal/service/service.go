package service

import (
	"qd_authentication_api/internal/repository"
)

type Servicer interface {
	GetAuthenticationService() AuthenticationServicer
	Close() error
}

type Service struct {
	authenticationService AuthenticationServicer
	repository            repository.Repositoryer
}

func (service *Service) GetAuthenticationService() AuthenticationServicer {
	return service.authenticationService
}

func (service *Service) Close() error {
	if service.repository != nil {
		return service.repository.Close()
	}
	return nil
}

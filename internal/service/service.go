package service

import (
	"errors"

	"qd-authentication-api/internal/repository"
)

// Servicer is the interface for the service
type Servicer interface {
	GetAuthenticationService() AuthenticationServicer
	GetTokenService() TokenServicer
	Close() error
}

// Service is the implementation of the service
type Service struct {
	authenticationService AuthenticationServicer
	tokenService          TokenServicer
	repository            repository.Storer
}

var _ Servicer = &Service{}

// GetAuthenticationService Returns the authentication service
func (service *Service) GetAuthenticationService() AuthenticationServicer {
	return service.authenticationService
}

func (service *Service) GetTokenService() TokenServicer {
	return service.tokenService
}

// Close closes the service
func (service *Service) Close() error {
	if service.repository != nil {
		return service.repository.Close()
	}
	return errors.New("Service repository is nil")
}

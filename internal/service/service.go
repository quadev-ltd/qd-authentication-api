package service

import (
	"errors"
	"qd-authentication-api/internal/repository"
)

// Servicer is the interface for the service
type Servicer interface {
	GetAuthenticationService() AuthenticationServicer
	Close() error
}

// Service is the implementation of the service
type Service struct {
	authenticationService AuthenticationServicer
	repository            repository.Repositoryer
}

var _ Servicer = &Service{}

// GetAuthenticationService Returns the authentication service
func (service *Service) GetAuthenticationService() AuthenticationServicer {
	return service.authenticationService
}

// Close closes the service
func (service *Service) Close() error {
	if service.repository != nil {
		return service.repository.Close()
	}
	return errors.New("Service repository is nil")
}

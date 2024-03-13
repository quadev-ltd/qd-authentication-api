package service

import (
	"errors"

	"qd-authentication-api/internal/repository"
)

// Servicer is the interface for the service
type Servicer interface {
	GetAuthenticationService() UserServicer
	GetTokenService() TokenServicer
	GetPasswordService() PasswordServicer
	Close() error
}

// Service is the implementation of the service
type Service struct {
	userService     UserServicer
	tokenService    TokenServicer
	passwordService PasswordServicer
	repository      repository.Storer
}

var _ Servicer = &Service{}

// GetAuthenticationService Returns the authentication service
func (service *Service) GetAuthenticationService() UserServicer {
	return service.userService
}

// GetTokenService Returns the token service
func (service *Service) GetTokenService() TokenServicer {
	return service.tokenService
}

// GetPasswordService Returns the password service
func (service *Service) GetPasswordService() PasswordServicer {
	return service.passwordService
}

// Close closes the service
func (service *Service) Close() error {
	if service.repository != nil {
		return service.repository.Close()
	}
	return errors.New("Service repository is nil")
}

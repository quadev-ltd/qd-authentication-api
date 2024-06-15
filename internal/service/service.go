package service

import (
	"errors"

	"qd-authentication-api/internal/firebase"
	"qd-authentication-api/internal/repository"
)

// Managerer is the interface for the service
type Managerer interface {
	GetUserService() UserServicer
	GetFirebaseAuthService() firebase.AuthServicer
	GetTokenService() TokenServicer
	GetPasswordService() PasswordServicer
	Close() error
}

// Manager is the implementation of the service
type Manager struct {
	userService         UserServicer
	firebaseAuthService firebase.AuthServicer
	tokenService        TokenServicer
	passwordService     PasswordServicer
	emailService        EmailServicer
	repository          repository.Storer
}

var _ Managerer = &Manager{}

// GetUserService Returns the authentication service
func (service *Manager) GetUserService() UserServicer {
	return service.userService
}

// GetFirebaseAuthService Returns firebase authentication service
func (service *Manager) GetFirebaseAuthService() firebase.AuthServicer {
	return service.firebaseAuthService
}

// GetTokenService Returns the token service
func (service *Manager) GetTokenService() TokenServicer {
	return service.tokenService
}

// GetPasswordService Returns the password service
func (service *Manager) GetPasswordService() PasswordServicer {
	return service.passwordService
}

// Close closes the services
func (service *Manager) Close() error {
	if service.repository == nil {
		return errors.New("Service repository is nil")
	}
	err := service.repository.Close()
	if err != nil {
		return err
	}
	if service.emailService == nil {
		return errors.New("Email service is nil")
	}
	err = service.emailService.Close()
	if err != nil {
		return err
	}
	return nil
}

package repository

import (
	"qd-authentication-api/internal/config"
)

// StoreFactoryer is the interface for the repository factory
type StoreFactoryer interface {
	CreateRepositoryStore(config *config.Config) (Storer, error)
}

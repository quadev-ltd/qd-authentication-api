package repository

import (
	"qd-authentication-api/internal/config"
)

// RepositoryStoreFactoryer is the interface for the repository factory
type RepositoryStoreFactoryer interface {
	CreateRepositoryStore(config *config.Config) (RepositoryStorer, error)
}

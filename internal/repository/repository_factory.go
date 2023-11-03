package repository

import (
	"qd_authentication_api/internal/config"
)

// Factoryer is the interface for the repository factory
type Factoryer interface {
	CreateRepository(config *config.Config) (Repositoryer, error)
}

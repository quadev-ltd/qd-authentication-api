package repository

import (
	"qd-authentication-api/internal/config"
)

// Factoryer is the interface for the repository factory
type Factoryer interface {
	CreateRepository(config *config.Config) (Repositoryer, error)
}

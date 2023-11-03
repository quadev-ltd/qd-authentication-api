package repository

import (
	"qd_authentication_api/internal/config"
)

type RepositoryFactoryer interface {
	CreateRepository(config *config.Config) (Repositoryer, error)
}

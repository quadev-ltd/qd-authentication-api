package repository

type Repositoryer interface {
	GetUserRepository() UserRepositoryer
	Close() error
}

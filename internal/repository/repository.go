package repository

// Repositoryer is the interface for the repository
type Repositoryer interface {
	GetUserRepository() UserRepositoryer
	Close() error
}

package repository

// RepositoryStorer is the interface for the repository
type RepositoryStorer interface {
	GetUserRepository() UserRepositoryer
	GetTokenRepository() TokenRepositoryer
	Close() error
}

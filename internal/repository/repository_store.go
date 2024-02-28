package repository

// Storer is the interface for the repository
type Storer interface {
	GetUserRepository() UserRepositoryer
	GetTokenRepository() TokenRepositoryer
	Close() error
}

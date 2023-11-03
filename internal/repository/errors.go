package repository

type RepositoryError struct {
	Message string
}

func (e *RepositoryError) Error() string {
	return e.Message
}

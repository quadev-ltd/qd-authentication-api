package repository

import "context"

// Repositoryer is the interface for the repository
type Repositoryer interface {
	Insert(ctx context.Context, document interface{}) (interface{}, error)
}

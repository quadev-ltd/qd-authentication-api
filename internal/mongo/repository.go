package mongo

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/mongo"

	"qd-authentication-api/internal/repository"
)

// Repository is a mongo specific token repository
type Repository struct {
	dbName         string
	collectionName string
	client         *mongo.Client
}

var _ repository.Repositoryer = &Repository{}

// NewRepository creates a new mongo token repository
func NewRepository(client *mongo.Client, dbName string, collectionName string) *Repository {
	return &Repository{dbName, collectionName, client}
}

func (repository *Repository) getCollection() *mongo.Collection {
	return repository.client.Database(
		repository.dbName,
	).Collection(repository.collectionName)
}

// Insert creates a new token in the mongo database
func (repository *Repository) Insert(ctx context.Context, document interface{}) (interface{}, error) {
	collection := repository.getCollection()
	result, err := collection.InsertOne(ctx, document)
	if err != nil {
		return nil, fmt.Errorf("Insertion error: %v", err)
	}
	return result.InsertedID, nil
}

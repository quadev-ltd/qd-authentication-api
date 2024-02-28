package mongo

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/repository"
)

// TokenRepository is a mongo specific token repository
type TokenRepository struct {
	dbName         string
	collectionName string
	client         *mongo.Client
}

var _ repository.TokenRepositoryer = &TokenRepository{}

// NewTokenRepository creates a new mongo token repository
func NewTokenRepository(client *mongo.Client) *TokenRepository {
	return &TokenRepository{client: client, dbName: "qd_authentication", collectionName: "token"}
}

func (tokenRepository *TokenRepository) getCollection() *mongo.Collection {
	return tokenRepository.client.Database(
		tokenRepository.dbName,
	).Collection(tokenRepository.collectionName)
}

// Create creates a new token in the mongo database
func (tokenRepository *TokenRepository) Create(ctx context.Context, token *model.Token) error {
	collection := tokenRepository.getCollection()
	_, err := collection.InsertOne(ctx, token)
	if err != nil {
		return fmt.Errorf("Insertion error: %v", err)
	}
	return nil
}

// GetByToken gets a token by its value
func (tokenRepository *TokenRepository) GetByToken(ctx context.Context, token string) (*model.Token, error) {
	collection := tokenRepository.getCollection()

	filter := bson.M{"token": token}
	var foundToken model.Token

	err := collection.FindOne(ctx, filter).Decode(&foundToken)
	if err != nil {
		return nil, fmt.Errorf("Error finding token by email: %v", err)
	}

	return &foundToken, nil
}

// Update updates a token in the mongo database
func (tokenRepository *TokenRepository) Update(ctx context.Context, token *model.Token) error {
	collection := tokenRepository.getCollection()
	filter := bson.M{"token": token.Token, "userId": token.UserID}
	update := bson.M{
		"$set": bson.M{
			"issuedAt":  token.IssuedAt,
			"expiresAt": token.ExpiresAt,
			"revoked":   token.Revoked,
			"type":      token.Type,
		},
	}

	updateResult, resultError := collection.UpdateOne(ctx, filter, update)
	if resultError != nil {
		return fmt.Errorf("Error updating token: %v", resultError)
	}
	if updateResult.MatchedCount == 0 {
		return &repository.Error{
			Message: "No token was found",
		}
	}
	return nil
}

// Remove removes a token from the mongo database
func (tokenRepository *TokenRepository) Remove(ctx context.Context, token string) error {
	collection := tokenRepository.getCollection()
	filter := bson.M{"token": token}

	result, err := collection.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("could not delete token: %v", err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("no token found with specified value")
	}

	return nil
}

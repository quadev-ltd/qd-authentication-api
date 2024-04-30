package mongo

import (
	"context"
	"fmt"

	commonToken "github.com/quadev-ltd/qd-common/pkg/token"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/repository"
)

// TokenRepository is a mongo specific token repository
type TokenRepository struct {
	*Repository
}

var _ repository.TokenRepositoryer = &TokenRepository{}

// NewTokenRepository creates a new mongo token repository
func NewTokenRepository(client *mongo.Client) *TokenRepository {
	return &TokenRepository{
		Repository: NewRepository(client, "qd_authentication", "token"),
	}
}

// InsertToken creates a new token in the mongo database
func (tokenRepository *TokenRepository) InsertToken(ctx context.Context, token *model.Token) (interface{}, error) {
	return tokenRepository.Insert(ctx, token)
}

// GetByToken gets a token by its value
func (tokenRepository *TokenRepository) GetByToken(ctx context.Context, token string) (*model.Token, error) {
	collection := tokenRepository.getCollection()

	filter := bson.M{"token_hash": token}
	var foundToken model.Token

	err := collection.FindOne(ctx, filter).Decode(&foundToken)
	if err != nil {
		return nil, fmt.Errorf("Error finding token by email: %v", err)
	}

	return &foundToken, nil
}

// GetByUserIDAndTokenType gets a token by its value
func (tokenRepository *TokenRepository) GetByUserIDAndTokenType(
	ctx context.Context,
	userID primitive.ObjectID,
	tokenType commonToken.Type,
) (*model.Token, error) {
	collection := tokenRepository.getCollection()

	filter := bson.M{"userID": userID, "type": tokenType}
	var foundToken model.Token

	err := collection.FindOne(ctx, filter).Decode(&foundToken)
	if err != nil {
		return nil, fmt.Errorf("Error finding token by userID and token_hash: %v", err)
	}

	return &foundToken, nil
}

// Update updates a token in the mongo database
func (tokenRepository *TokenRepository) Update(ctx context.Context, token *model.Token) error {
	collection := tokenRepository.getCollection()
	filter := bson.M{
		"token_hash": token.TokenHash,
		"userID":     token.UserID,
	}
	update := bson.M{
		"$set": bson.M{
			"issued_at":  token.IssuedAt,
			"expires_at": token.ExpiresAt,
			"revoked":    token.Revoked,
			"type":       token.Type,
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
func (tokenRepository *TokenRepository) Remove(ctx context.Context, token *model.Token) error {
	collection := tokenRepository.getCollection()
	filter := bson.M{"userID": token.UserID, "token_hash": token.TokenHash, "type": token.Type}

	result, err := collection.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("could not delete token: %v", err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("no token found with specified value")
	}

	return nil
}

// RemoveAllByUserIDAndTokenType deletes all tokens for a given userID and tokenType in the mongo database
func (tokenRepository *TokenRepository) RemoveAllByUserIDAndTokenType(
	ctx context.Context,
	userID primitive.ObjectID,
	tokenType commonToken.Type,
) error {
	collection := tokenRepository.getCollection()
	filter := bson.M{"userID": userID, "type": tokenType}

	_, err := collection.DeleteMany(ctx, filter)
	if err != nil {
		return fmt.Errorf("could not delete tokens: %v", err)
	}
	return nil
}

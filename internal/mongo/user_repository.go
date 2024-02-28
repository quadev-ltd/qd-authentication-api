package mongo

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/repository"
)

// UserRepository is a mongo specific user repository
type UserRepository struct {
	*Repository
}

var _ repository.UserRepositoryer = &UserRepository{}

// NewUserRepository creates a new mongo user repository
func NewUserRepository(client *mongo.Client) *UserRepository {
	return &UserRepository{
		Repository: NewRepository(client, "qd_authentication", "user"),
	}
}

// InsertUser creates a new user in the mongo database
func (userRepository *UserRepository) InsertUser(ctx context.Context, user *model.User) (interface{}, error) {
	return userRepository.Insert(ctx, user)
}

// GetByEmail gets a user by email from the mongo database
func (userRepository *UserRepository) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	collection := userRepository.getCollection()

	filter := bson.M{"email": email}
	var foundUser model.User

	err := collection.FindOne(ctx, filter).Decode(&foundUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, fmt.Errorf("Error finding user by email: %v", err)
	}

	return &foundUser, nil
}

// GetByUserID gets a user by verification token from the mongo database
func (userRepository *UserRepository) GetByUserID(ctx context.Context, userID primitive.ObjectID) (*model.User, error) {
	collection := userRepository.getCollection()
	filter := bson.M{"_id": userID}
	var foundUser model.User

	resultError := collection.FindOne(ctx, filter).Decode(&foundUser)
	if resultError != nil {
		return nil, fmt.Errorf("Error finding user by verification token: %v", resultError)
	}

	return &foundUser, nil
}

// Update updates a user in the mongo database
func (userRepository *UserRepository) Update(ctx context.Context, user *model.User) error {
	collection := userRepository.getCollection()
	filter := bson.M{"email": user.Email}
	update := bson.M{
		"$set": bson.M{
			"accountstatus": user.AccountStatus,
			"refreshtokens": user.RefreshTokens,
		},
	}

	updateResult, resultError := collection.UpdateOne(ctx, filter, update)
	if resultError != nil {
		return fmt.Errorf("Error updating user: %v", resultError)
	}
	if updateResult.MatchedCount == 0 {
		return &repository.Error{
			Message: "No account was found",
		}
	}
	return nil
}

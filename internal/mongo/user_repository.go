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
	dbName         string
	collectionName string
	client         *mongo.Client
}

var _ repository.UserRepositoryer = &UserRepository{}

// NewUserRepository creates a new mongo user repository
func NewUserRepository(client *mongo.Client) *UserRepository {
	return &UserRepository{client: client, dbName: "qd_authentication", collectionName: "user"}
}

func (userRepository *UserRepository) getCollection() *mongo.Collection {
	return userRepository.client.Database(
		userRepository.dbName,
	).Collection(userRepository.collectionName)
}

// Create creates a new user in the mongo database
func (userRepository *UserRepository) Create(ctx context.Context, user *model.User) (interface{}, error) {
	collection := userRepository.getCollection()
	result, err := collection.InsertOne(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("Insertion error: %v", err)
	}
	return result.InsertedID, nil
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

// GetByVerificationToken gets a user by verification token from the mongo database
func (userRepository *UserRepository) GetByUserId(ctx context.Context, userId primitive.ObjectID) (*model.User, error) {
	collection := userRepository.getCollection()
	filter := bson.M{"_id": userId}
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

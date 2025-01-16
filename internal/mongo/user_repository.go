package mongo

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

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

// ExistsByEmail checks if a user exists by email in the mongo database
func (userRepository *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	collection := userRepository.getCollection()

	filter := bson.M{"email": email}
	count, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		return false, fmt.Errorf("Error checking user existence by email: %v", err)
	}

	return count > 0, nil
}

// GetByEmail gets a user by email from the mongo database, returns nil if user is not found
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

// UpdateStatus updates a user in the mongo database
func (userRepository *UserRepository) UpdateStatus(ctx context.Context, user *model.User) error {
	update := bson.M{
		"$set": bson.M{
			"accountStatus": user.AccountStatus,
		},
	}

	return userRepository.Update(ctx, user, update)
}

// UpdatePassword updates a user in the mongo database
func (userRepository *UserRepository) UpdatePassword(ctx context.Context, user *model.User) error {
	update := bson.M{
		"$set": bson.M{
			"passwordHash": user.PasswordHash,
			"passwordSalt": user.PasswordSalt,
			"authTypes":    user.AuthTypes,
		},
	}
	return userRepository.Update(ctx, user, update)
}

// UpdateAuthTypes updates a user in the mongo database
func (userRepository *UserRepository) UpdateAuthTypes(ctx context.Context, user *model.User) error {
	update := bson.M{
		"$set": bson.M{
			"authTypes": user.AuthTypes,
		},
	}
	return userRepository.Update(ctx, user, update)
}

// UpdateProfileDetails updates a user in the mongo database
func (userRepository *UserRepository) UpdateProfileDetails(
	ctx context.Context,
	user *model.User,
) (*model.User, error) {
	update := bson.M{
		"$set": bson.M{
			"firstName":   user.FirstName,
			"lastName":    user.LastName,
			"dateOfBirth": user.DateOfBirth,
		},
	}
	collection := userRepository.getCollection()
	filter := bson.M{"_id": user.ID}

	after := options.After
	opts := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
	}

	var updatedUser model.User
	err := collection.FindOneAndUpdate(ctx, filter, update, &opts).
		Decode(&updatedUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, &repository.Error{
				Message: "No account was found",
			}
		}
		return nil, fmt.Errorf("error updating user: %v", err)
	}

	return &updatedUser, nil
}

// Update updates a user in the mongo database
func (userRepository *UserRepository) Update(ctx context.Context, user *model.User, dataUpdate primitive.M) error {
	collection := userRepository.getCollection()
	filter := bson.M{"_id": user.ID}

	updateResult, resultError := collection.UpdateOne(ctx, filter, dataUpdate)
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

// GetByUserID gets a user by verification token from the mongo database
func (userRepository *UserRepository) DeleteByUserID(ctx context.Context, userID primitive.ObjectID) error {
	collection := userRepository.getCollection()
	filter := bson.M{"_id": userID}

	_, resultError := collection.DeleteOne(ctx, filter)
	if resultError != nil {
		return fmt.Errorf("Error deleting user by ID %s: %v", userID.Hex(), resultError)
	}

	return nil
}

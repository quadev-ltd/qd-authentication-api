package mongo

import (
	"context"
	"qd_authentication_api/internal/model"
	"qd_authentication_api/internal/repository"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type UserRepository struct {
	dbName         string
	collectionName string
	client         *mongo.Client
}

var _ repository.UserRepositoryer = &UserRepository{}

func NewUserRepository(client *mongo.Client) *UserRepository {
	return &UserRepository{client: client, dbName: "qd_authentication", collectionName: "user"}
}

func (userRepository *UserRepository) getCollection() *mongo.Collection {
	return userRepository.client.Database(
		userRepository.dbName,
	).Collection(userRepository.collectionName)
}

func (userRepository *UserRepository) Create(user *model.User) error {
	collection := userRepository.getCollection()
	_, err := collection.InsertOne(context.Background(), user)
	if err != nil {
		// TODO log
		return &repository.RepositoryError{
			Message: "Insertion Error",
		}
	}
	return nil
}

func (userRepository *UserRepository) GetByEmail(email string) (*model.User, error) {
	collection := userRepository.getCollection()

	filter := bson.M{"email": email}
	var foundUser model.User

	err := collection.FindOne(context.Background(), filter).Decode(&foundUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		// TODO log err
		return nil, &repository.RepositoryError{
			Message: "There has been an error trying to find user by email.",
		}
	}

	return &foundUser, nil
}

func (userRepository *UserRepository) GetByVerificationToken(verificationToken string) (*model.User, error) {
	collection := userRepository.getCollection()
	filter := bson.M{"verificationtoken": verificationToken}
	var foundUser model.User

	resultError := collection.FindOne(context.Background(), filter).Decode(&foundUser)
	if resultError != nil {
		if resultError == mongo.ErrNoDocuments {
			return nil, nil
		}
		// TODO log
		return nil, &repository.RepositoryError{
			Message: "There has been an error trying to find user by token.",
		}
	}

	return &foundUser, nil
}

func (userRepository *UserRepository) Update(user *model.User) error {
	collection := userRepository.getCollection()
	filter := bson.M{"email": user.Email}
	update := bson.M{"$set": bson.M{"accountstatus": user.AccountStatus}}

	updateResult, resultError := collection.UpdateOne(context.Background(), filter, update)
	if resultError != nil {
		// TODO log updateError
		return &repository.RepositoryError{
			Message: "There has been an error trying to update the user.",
		}
	}
	if updateResult.MatchedCount == 0 {
		return &repository.RepositoryError{
			Message: "No account was found",
		}
	}
	return nil
}

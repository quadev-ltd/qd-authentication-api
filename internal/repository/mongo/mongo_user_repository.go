package mongo

import (
	"context"
	"errors"
	"qd_authentication_api/internal/model"
	"qd_authentication_api/internal/repository"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type MongoUserRepository struct {
	dbName         string
	collectionName string
	client         *mongo.Client
}

var _ repository.UserRepository = &MongoUserRepository{}

func NewMongoUserRepository(client *mongo.Client) *MongoUserRepository {
	return &MongoUserRepository{client: client, dbName: "qd_authentication", collectionName: "users"}
}

func (mongoUserRepository *MongoUserRepository) Create(user *model.User) error {
	collection := mongoUserRepository.client.Database(mongoUserRepository.dbName).Collection("users")
	_, err := collection.InsertOne(context.Background(), user)
	return err
}

func (mongoUserRepository *MongoUserRepository) GetByEmail(email string) (*model.User, error) {
	collection := mongoUserRepository.client.Database(mongoUserRepository.dbName).Collection("users")
	filter := bson.M{"email": email}
	var foundUser model.User

	err := collection.FindOne(context.Background(), filter).Decode(&foundUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return &foundUser, nil
}

package mongo

import (
	"context"
	"errors"
	"qd_authentication_api/internal/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type MongoUserRepository struct {
	dbName         string
	collectionName string
	client         *mongo.Client
}

func NewMongoUserRepository(client *mongo.Client) *MongoUserRepository {
	return &MongoUserRepository{client: client, dbName: "qd_authentication", collectionName: "user"}
}

func (mongoUserRepository *MongoUserRepository) Create(user *model.User) error {
	collection := mongoUserRepository.client.Database(mongoUserRepository.dbName).Collection(mongoUserRepository.collectionName)
	_, err := collection.InsertOne(context.Background(), user)
	return err
}

func (mongoUserRepository *MongoUserRepository) GetByEmail(email string) (*model.User, error) {
	collection := mongoUserRepository.client.Database(mongoUserRepository.dbName).Collection(mongoUserRepository.collectionName)
	filter := bson.M{"email": email}
	var foundUser model.User

	err := collection.FindOne(context.Background(), filter).Decode(&foundUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}

	return &foundUser, nil
}

func (mongoUserRepository *MongoUserRepository) GetByVerificationToken(verificationToken string) (*model.User, error) {
	collection := mongoUserRepository.client.Database(mongoUserRepository.dbName).Collection(mongoUserRepository.collectionName)
	filter := bson.M{"verificationtoken": verificationToken}
	var foundUser model.User

	resultError := collection.FindOne(context.Background(), filter).Decode(&foundUser)
	if resultError != nil {
		if resultError == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, resultError
	}

	return &foundUser, nil
}

func (mongoUserRepository *MongoUserRepository) Update(user *model.User) error {
	collection := mongoUserRepository.client.Database(mongoUserRepository.dbName).Collection(mongoUserRepository.collectionName)
	filter := bson.M{"email": user.Email}
	update := bson.M{"$set": bson.M{"accountstatus": user.AccountStatus}}

	updateResult, resultError := collection.UpdateOne(context.Background(), filter, update)
	if resultError != nil {
		return resultError
	}
	if updateResult.MatchedCount == 0 {
		return errors.New("No account was found")
	}
	return nil
}

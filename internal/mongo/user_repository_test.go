package mongo

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/mongo/mock"
)

func TestMongoUserRepository(test *testing.T) {
	test.Run("Insert", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		repo := NewUserRepository(client)

		user := model.NewUser()

		// Test Insert
		insertedID, err := repo.InsertUser(context.Background(), user)
		assert.NoError(test, err)
		id, ok := insertedID.(primitive.ObjectID)
		assert.True(test, ok)
		assert.NotNil(test, id)

		// Test GetByEmail
		foundUser, err := repo.GetByEmail(context.Background(), user.Email)
		assert.NoError(test, err)
		assert.NotNil(test, foundUser)
		assert.Equal(test, user.Email, foundUser.Email)
	})
	test.Run("GetByEmail Not Found", func(test *testing.T) {
		mongoServer, client, error := mock.SetupMockMongoServerAndClient(test)
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		repo := NewUserRepository(client)

		// Test GetByEmail
		email := "notfound@example.com"
		user, error := repo.GetByEmail(context.Background(), email)
		assert.Nil(test, error)
		assert.Nil(test, user)
	})
	test.Run("GetUserByUserID", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		repo := NewUserRepository(client)

		user := model.NewUser()

		// Test Insert
		insertedID, err := repo.InsertUser(context.Background(), user)
		assert.NoError(test, err)
		id, ok := insertedID.(primitive.ObjectID)
		assert.True(test, ok)
		assert.NotNil(test, id)

		// Test GetUserByVerificationToken
		foundUser, err := repo.GetByUserID(context.Background(), id)
		assert.NoError(test, err)
		assert.NotNil(test, foundUser)
		assert.Equal(test, id.Hex(), foundUser.ID.Hex())
	})
	test.Run("Update Success", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()
		repo := NewUserRepository(client)
		user := model.NewUser()

		insertedID, err := repo.InsertUser(context.Background(), user)
		assert.NoError(test, err)
		id, ok := insertedID.(primitive.ObjectID)
		assert.True(test, ok)
		assert.NotNil(test, id)

		user.AccountStatus = model.AccountStatusUnverified

		err = repo.Update(context.Background(), user)
		assert.NoError(test, err)

		foundUser, err := repo.GetByEmail(context.Background(), user.Email)
		assert.NoError(test, err)
		assert.NotNil(test, foundUser)
		assert.Equal(test, user.AccountStatus, foundUser.AccountStatus)
	})
	test.Run("Update User Not Found", func(test *testing.T) {
		mongoServer, client, error := mock.SetupMockMongoServerAndClient(test)
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		repo := NewUserRepository(client)

		user := model.NewUser()

		// Test Update
		error = repo.Update(context.Background(), user)
		assert.Error(test, error)
		assert.Equal(test, "No account was found", error.Error())
		// Assert error type
	})
}

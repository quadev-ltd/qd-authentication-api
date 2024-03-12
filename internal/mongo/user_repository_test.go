package mongo

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/mongo/mock"
)

func TestMongoUserRepository(test *testing.T) {
	test.Run("Insert", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		if err != nil {
			test.Fatal(err)
		}
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
	test.Run("GetByEmail_Not_Found", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		if err != nil {
			test.Fatal(err)
		}
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		repo := NewUserRepository(client)

		// Test GetByEmail
		email := "notfound@example.com"
		user, err := repo.GetByEmail(context.Background(), email)
		assert.Nil(test, err)
		assert.Nil(test, user)
	})
	test.Run("GetByEmail_Success", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		if err != nil {
			test.Fatal(err)
		}
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()
		repo := NewUserRepository(client)
		user := model.NewUser()
		_, err = repo.InsertUser(context.Background(), user)
		assert.NoError(test, err)

		// Test GetByEmail
		foundUser, err := repo.GetByEmail(context.Background(), user.Email)
		assert.Nil(test, err)
		assert.Equal(test, user.Email, foundUser.Email)
	})
	test.Run("ExistsByEmail_Success", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		if err != nil {
			test.Fatal(err)
		}
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()
		repo := NewUserRepository(client)
		user := model.NewUser()
		_, err = repo.InsertUser(context.Background(), user)
		assert.NoError(test, err)

		// Test GetByEmail
		foundUser, err := repo.ExistsByEmail(context.Background(), user.Email)
		assert.Nil(test, err)
		assert.True(test, foundUser)
	})
	test.Run("ExistsByEmail_NotFound", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		if err != nil {
			test.Fatal(err)
		}
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()
		repo := NewUserRepository(client)

		// Test GetByEmail
		foundUser, err := repo.ExistsByEmail(context.Background(), "test@email.com")
		assert.Nil(test, err)
		assert.False(test, foundUser)
	})
	test.Run("GetUserByUserID", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		if err != nil {
			test.Fatal(err)
		}
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
	test.Run("UpdateStatus_Success", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		if err != nil {
			test.Fatal(err)
		}
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

		err = repo.UpdateStatus(context.Background(), user)
		assert.NoError(test, err)

		foundUser, err := repo.GetByEmail(context.Background(), user.Email)
		assert.NoError(test, err)
		assert.NotNil(test, foundUser)
		assert.Equal(test, user.AccountStatus, foundUser.AccountStatus)
	})
	test.Run("UpdateStatus_User_Not_Found", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		if err != nil {
			test.Fatal(err)
		}
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		repo := NewUserRepository(client)

		user := model.NewUser()

		// Test UpdateStatus
		err = repo.UpdateStatus(context.Background(), user)
		assert.Error(test, err)
		assert.Equal(test, "No account was found", err.Error())

	})

	test.Run("UpdatePassword_Success", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		if err != nil {
			test.Fatal(err)
		}
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()
		repo := NewUserRepository(client)
		user := model.NewUser()

		insertedID, err := repo.InsertUser(context.Background(), user)
		assert.NoError(test, err)
		id, ok := insertedID.(primitive.ObjectID)
		assert.True(test, ok)
		assert.NotNil(test, id)

		newHash := "new-hash"
		newSalt := "new-salt"
		user.PasswordHash = newHash
		user.PasswordSalt = newSalt

		err = repo.UpdatePassword(context.Background(), user)
		assert.NoError(test, err)

		foundUser, err := repo.GetByEmail(context.Background(), user.Email)
		assert.NoError(test, err)
		assert.NotNil(test, foundUser)
		assert.Equal(test, user.PasswordHash, newHash)
		assert.Equal(test, user.PasswordSalt, newSalt)
	})
	test.Run("UpdatePassword_User_Not_Found", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		if err != nil {
			test.Fatal(err)
		}
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		repo := NewUserRepository(client)

		user := model.NewUser()

		// Test UpdatePassword
		err = repo.UpdatePassword(context.Background(), user)
		assert.Error(test, err)
		assert.Equal(test, "No account was found", err.Error())
	})

	// UpdateProfileDetails
	test.Run("UpdateProfileDetails_Success", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		if err != nil {
			test.Fatal(err)
		}
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()
		repo := NewUserRepository(client)
		user := model.NewUser()

		insertedID, err := repo.InsertUser(context.Background(), user)
		assert.NoError(test, err)

		id, ok := insertedID.(primitive.ObjectID)
		assert.True(test, ok)
		assert.NotNil(test, id)

		newBirthDay := time.Now()
		newFirstName := "new-first-name"
		newLastName := "new-last-name"
		user.DateOfBirth = newBirthDay
		user.FirstName = newFirstName
		user.LastName = newLastName

		err = repo.UpdateProfileDetails(context.Background(), user)
		assert.NoError(test, err)

		foundUser, err := repo.GetByEmail(context.Background(), user.Email)
		assert.NoError(test, err)
		assert.NotNil(test, foundUser)
		assert.Equal(test, user.DateOfBirth.Unix(), newBirthDay.Unix())
		assert.Equal(test, user.FirstName, newFirstName)
		assert.Equal(test, user.LastName, newLastName)
	})

	test.Run("UpdateProfileDetails_User_Not_Found", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		if err != nil {
			test.Fatal(err)
		}
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		repo := NewUserRepository(client)

		user := model.NewUser()

		// Test UpdatePassword
		err = repo.UpdateProfileDetails(context.Background(), user)
		assert.Error(test, err)
		assert.Equal(test, "No account was found", err.Error())
	})
}

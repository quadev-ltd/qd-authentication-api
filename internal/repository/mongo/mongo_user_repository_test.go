package mongo

import (
	"context"
	"qd_authentication_api/internal/model"
	"testing"
	"time"

	"github.com/benweissmann/memongo"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func newUser() *model.User {
	return &model.User{
		Email:             "test@example.com",
		VerificationToken: "token",
		PasswordHash:      "hash",
		PasswordSalt:      "salt",
		FirstName:         "Test",
		LastName:          "User",
		DateOfBirth:       time.Now(),
		RegistrationDate:  time.Now(),
		LastLoginDate:     time.Now(),
		AccountStatus:     model.AccountStatusVerified,
	}
}

func setupMongoServer() (*memongo.Server, *mongo.Client, error) {
	// Start mongo server
	mongoServer, err := memongo.StartWithOptions(
		&memongo.Options{
			LogLevel:     4,
			MongoVersion: "4.0.5",
		},
	)
	if err != nil {
		return nil, nil, err
	}

	// Create a new mongo client
	client, err := mongo.NewClient(options.Client().ApplyURI(mongoServer.URI()))
	if err != nil {
		mongoServer.Stop()
		return nil, nil, err
	}

	// Connect the mongo client
	if err := client.Connect(context.Background()); err != nil {
		client.Disconnect(context.Background())
		mongoServer.Stop()
		return nil, nil, err
	}

	return mongoServer, client, nil
}

func testMongoUserRepository_Create(test *testing.T) {
	mongoServer, client, error := setupMongoServer()
	defer client.Disconnect(context.Background())
	defer mongoServer.Stop()

	repo := NewMongoUserRepository(client)

	user := newUser()

	// Test Create
	error = repo.Create(user)
	assert.NoError(test, error)

	// Test GetByEmail
	foundUser, error := repo.GetByEmail(user.Email)
	assert.NoError(test, error)
	assert.NotNil(test, foundUser)
	assert.Equal(test, user.Email, foundUser.Email)
}

func testMongoUserRepository_GetByEmail_NotFound(test *testing.T) {
	mongoServer, client, error := setupMongoServer()
	defer client.Disconnect(context.Background())
	defer mongoServer.Stop()

	repo := NewMongoUserRepository(client)

	// Test GetByEmail
	email := "notfound@example.com"
	user, error := repo.GetByEmail(email)
	assert.Nil(test, error)
	assert.Nil(test, user)
}

func testMongoUserRepository_GetUserByVerificationToken(test *testing.T) {
	mongoServer, client, error := setupMongoServer()
	defer client.Disconnect(context.Background())
	defer mongoServer.Stop()

	repo := NewMongoUserRepository(client)

	user := newUser()

	// Test Create
	error = repo.Create(user)
	assert.NoError(test, error)

	// Test GetUserByVerificationToken
	foundUser, error := repo.GetByVerificationToken(user.VerificationToken)
	assert.NoError(test, error)
	assert.NotNil(test, foundUser)
	assert.Equal(test, user.VerificationToken, foundUser.VerificationToken)
}

func testMongoUserRepository_Update_Success(test *testing.T) {
	mongoServer, client, err := setupMongoServer()
	defer client.Disconnect(context.Background())
	defer mongoServer.Stop()
	repo := NewMongoUserRepository(client)
	user := newUser()
	err = repo.Create(user)
	assert.NoError(test, err)

	user.AccountStatus = model.AccountStatusUnverified

	err = repo.Update(user)
	assert.NoError(test, err)

	foundUser, err := repo.GetByEmail(user.Email)
	assert.NoError(test, err)
	assert.NotNil(test, foundUser)
	assert.Equal(test, user.AccountStatus, foundUser.AccountStatus)
}

func testMongoUserRepository_Update_UserNotFound(test *testing.T) {
	mongoServer, client, error := setupMongoServer()
	defer client.Disconnect(context.Background())
	defer mongoServer.Stop()

	repo := NewMongoUserRepository(client)

	user := newUser()

	// Test Update
	error = repo.Update(user)
	assert.Error(test, error)
	assert.Equal(test, "No account was found", error.Error())
}

func TestMongoUserRepository(test *testing.T) {
	test.Run("Create", testMongoUserRepository_Create)
	test.Run("GetByEmail Not Found", testMongoUserRepository_GetByEmail_NotFound)
	test.Run("GetUserByVerificationToken", testMongoUserRepository_GetUserByVerificationToken)
	test.Run("Update Success", testMongoUserRepository_Update_Success)
	test.Run("Update User Not Found", testMongoUserRepository_Update_UserNotFound)
}

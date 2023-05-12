package repository

import (
	"context"
	"qd_authentication_api/internal/model"
	"testing"
	"time"

	"github.com/benweissmann/memongo"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func TestMongoUserRepository_Create(test *testing.T) {
	// Setup
	mongoServer, error := memongo.Start("4.0.5")
	if error != nil {
		test.Fatalf("failed to start memongo: %v", error)
	}
	defer mongoServer.Stop()

	client, error := mongo.NewClient(options.Client().ApplyURI(mongoServer.URI()))
	if error != nil {
		test.Fatalf("failed to create mongo client: %v", error)
	}

	if error := client.Connect(context.Background()); error != nil {
		test.Fatalf("failed to connect mongo client: %v", error)
	}
	defer client.Disconnect(context.Background())

	repo := NewMongoUserRepository(client)

	user := &model.User{
		ID:               uuid.New(),
		Email:            "test@example.com",
		PasswordHash:     "hashed_password",
		PasswordSalt:     "salt",
		FirstName:        "John",
		LastName:         "Doe",
		RegistrationDate: time.Now(),
		AccountStatus:    model.AccountStatusActive,
	}

	// Test Create
	error = repo.Create(user)
	assert.NoError(test, error)

	// Test GetByEmail
	foundUser, error := repo.GetByEmail(user.Email)
	assert.NoError(test, error)
	assert.NotNil(test, foundUser)
	assert.Equal(test, user.Email, foundUser.Email)
}

func TestMongoUserRepository_GetByEmail_NotFound(test *testing.T) {
	// Setup
	mongoServer, error := memongo.Start("4.0.5")
	if error != nil {
		test.Fatalf("failed to start memongo: %v", error)
	}
	defer mongoServer.Stop()

	client, error := mongo.NewClient(options.Client().ApplyURI(mongoServer.URI()))
	if error != nil {
		test.Fatalf("failed to create mongo client: %v", error)
	}

	if error := client.Connect(context.Background()); error != nil {
		test.Fatalf("failed to connect mongo client: %v", error)
	}
	defer client.Disconnect(context.Background())

	repo := NewMongoUserRepository(client)

	// Test GetByEmail
	email := "notfound@example.com"
	_, error = repo.GetByEmail(email)
	assert.Error(test, error)
}

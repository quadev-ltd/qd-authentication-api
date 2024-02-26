package mongo

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/mongo/mock"
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
		RefreshTokens:     []model.RefreshToken{},
	}
}

func TestMongoUserRepository(test *testing.T) {
	test.Run("Create", func(test *testing.T) {
		mongoServer, client, error := mock.SetupMockMongoServerAndClient(test)
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		repo := NewUserRepository(client)

		user := newUser()

		// Test Create
		error = repo.Create(context.Background(), user)
		assert.NoError(test, error)

		// Test GetByEmail
		foundUser, error := repo.GetByEmail(context.Background(), user.Email)
		assert.NoError(test, error)
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
	test.Run("GetUserByVerificationToken", func(test *testing.T) {
		mongoServer, client, error := mock.SetupMockMongoServerAndClient(test)
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		repo := NewUserRepository(client)

		user := newUser()

		// Test Create
		error = repo.Create(context.Background(), user)
		assert.NoError(test, error)

		// Test GetUserByVerificationToken
		foundUser, error := repo.GetByVerificationToken(context.Background(), user.VerificationToken)
		assert.NoError(test, error)
		assert.NotNil(test, foundUser)
		assert.Equal(test, user.VerificationToken, foundUser.VerificationToken)
	})
	test.Run("Update Success", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()
		repo := NewUserRepository(client)
		user := newUser()
		err = repo.Create(context.Background(), user)
		assert.NoError(test, err)

		user.AccountStatus = model.AccountStatusUnverified
		newRefreshToken := model.RefreshToken{
			Token:     "token",
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Hour * 24),
			Revoked:   false,
		}
		user.RefreshTokens = append(user.RefreshTokens, newRefreshToken)

		err = repo.Update(context.Background(), user)
		assert.NoError(test, err)

		foundUser, err := repo.GetByEmail(context.Background(), user.Email)
		assert.NoError(test, err)
		assert.NotNil(test, foundUser)
		assert.Equal(test, user.AccountStatus, foundUser.AccountStatus)
		assert.Equal(test, user.RefreshTokens[0].Token, foundUser.RefreshTokens[0].Token)
	})
	test.Run("Update User Not Found", func(test *testing.T) {
		mongoServer, client, error := mock.SetupMockMongoServerAndClient(test)
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		repo := NewUserRepository(client)

		user := newUser()

		// Test Update
		error = repo.Update(context.Background(), user)
		assert.Error(test, error)
		assert.Equal(test, "No account was found", error.Error())
		// Assert error type
	})
}

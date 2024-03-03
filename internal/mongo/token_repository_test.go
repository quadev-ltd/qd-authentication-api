package mongo

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/mongo/mock"
)

func TestMongoTokenRepository(test *testing.T) {
	test.Run("Create", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		repo := NewTokenRepository(client)

		token := model.NewToken("test_token")

		// Test Create
		_, err = repo.InsertToken(context.Background(), token)
		assert.NoError(test, err)

		// Test GetByEmail
		foundToken, err := repo.GetByToken(context.Background(), token.Token)
		assert.NoError(test, err)
		assert.NotNil(test, foundToken)
		assert.Equal(test, token.Token, foundToken.Token)
	})
	test.Run("GetByToken_Not_Found", func(test *testing.T) {
		mongoServer, client, error := mock.SetupMockMongoServerAndClient(test)
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		repo := NewTokenRepository(client)

		// Test GetByToken
		token := "notfound_token"
		user, error := repo.GetByToken(context.Background(), token)
		assert.Error(test, error)
		assert.Equal(test, "Error finding token by email: mongo: no documents in result", error.Error())
		assert.Nil(test, user)
	})
	test.Run("Update_Success", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()
		repo := NewTokenRepository(client)
		token := model.NewToken("test_token")

		_, err = repo.InsertToken(context.Background(), token)
		assert.NoError(test, err)

		issueAt := time.Now()
		expiresAt := time.Now().Add(33 * time.Hour)
		token.Type = model.RefreshTokenType
		token.Revoked = true
		token.IssuedAt = issueAt
		token.ExpiresAt = expiresAt

		err = repo.Update(context.Background(), token)
		assert.NoError(test, err)

		foundToken, err := repo.GetByToken(context.Background(), token.Token)
		assert.NoError(test, err)
		assert.NotNil(test, foundToken)
		assert.Equal(test, model.RefreshTokenType, foundToken.Type)
		assert.True(test, foundToken.Revoked)
		assert.Equal(test, issueAt, token.IssuedAt)
		assert.Equal(test, expiresAt, token.ExpiresAt)
	})
	test.Run("Update_User_Not_Found", func(test *testing.T) {
		mongoServer, client, error := mock.SetupMockMongoServerAndClient(test)
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		repo := NewTokenRepository(client)

		token := model.NewToken("test_token")

		// Test Update
		error = repo.Update(context.Background(), token)
		assert.Error(test, error)
		assert.Equal(test, "No token was found", error.Error())
		// Assert error type
	})
	test.Run("Remove", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()
		repo := NewTokenRepository(client)
		token := model.NewToken("test_token")

		_, err = repo.InsertToken(context.Background(), token)
		assert.NoError(test, err)

		err = repo.Remove(context.Background(), token.Token)
		assert.NoError(test, err)

		foundToken, err := repo.GetByToken(context.Background(), token.Token)
		assert.Error(test, err)
		assert.Equal(test, "Error finding token by email: mongo: no documents in result", err.Error())
		assert.Nil(test, foundToken)
	})
}

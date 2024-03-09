package mongo

import (
	"context"
	"testing"
	"time"

	commonToken "github.com/quadev-ltd/qd-common/pkg/token"
	"github.com/stretchr/testify/assert"

	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/mongo/mock"
)

func TestMongoTokenRepository(test *testing.T) {
	test.Run("Create_One_Success", func(test *testing.T) {
		ctx := context.Background()
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		if err != nil {
			test.Fatal()
		}
		defer client.Disconnect(ctx)
		defer mongoServer.Stop()

		repo := NewTokenRepository(client)

		token := model.NewToken("test_token_hash", "test_token_salt")

		// Test Create
		_, err = repo.InsertToken(ctx, token)
		if err != nil {
			test.Fatal(err)
		}

		// Test GetByUserIDAndTokenType
		foundToken, err := repo.GetByUserIDAndTokenType(context.Background(), token.UserID, token.Type)
		assert.NoError(test, err)
		assert.NotNil(test, foundToken)
		assert.Equal(test, token.UserID.Hex(), foundToken.UserID.Hex())
		assert.Equal(test, token.TokenHash, foundToken.TokenHash)
		assert.Equal(test, token.Salt, foundToken.Salt)
	})

	test.Run("Create_Three_Success", func(test *testing.T) {
		ctx := context.Background()
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		if err != nil {
			test.Fatal(err)
		}
		defer client.Disconnect(ctx)
		defer mongoServer.Stop()

		repo := NewTokenRepository(client)

		token := model.NewToken("test_token_hash", "test_token_salt")
		_, err = repo.InsertToken(ctx, token)
		if err != nil {
			test.Fatal(err)
		}

		tokenToSearch := model.NewToken("test_token_hash1", "test_token_salt1")
		_, err = repo.InsertToken(ctx, tokenToSearch)
		if err != nil {
			test.Fatal(err)
		}

		token = model.NewToken("test_token_hash2", "test_token_salt2")
		_, err = repo.InsertToken(ctx, token)
		if err != nil {
			test.Fatal(err)
		}

		foundToken, err := repo.GetByUserIDAndTokenType(ctx, tokenToSearch.UserID, tokenToSearch.Type)
		assert.NoError(test, err)
		assert.NotNil(test, foundToken)
		assert.Equal(test, tokenToSearch.TokenHash, foundToken.TokenHash)
		assert.Equal(test, tokenToSearch.Salt, foundToken.Salt)
	})

	test.Run("GetByToken_Not_Found", func(test *testing.T) {
		mongoServer, client, error := mock.SetupMockMongoServerAndClient(test)
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		repo := NewTokenRepository(client)

		// Test GetByToken
		token := model.NewToken("test_hash", "test_salt")
		user, error := repo.GetByUserIDAndTokenType(context.Background(), token.UserID, token.Type)
		assert.Error(test, error)
		assert.Equal(test, "Error finding token by user_id and token_hash: mongo: no documents in result", error.Error())
		assert.Nil(test, user)
	})
	test.Run("Update_Success", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()
		repo := NewTokenRepository(client)
		token := model.NewToken("test_token_hash", "test_token")

		_, err = repo.InsertToken(context.Background(), token)
		assert.NoError(test, err)

		issueAt := time.Now()
		expiresAt := time.Now().Add(33 * time.Hour)
		token.Type = commonToken.AccessTokenType
		token.Revoked = true
		token.IssuedAt = issueAt
		token.ExpiresAt = expiresAt

		err = repo.Update(context.Background(), token)
		assert.NoError(test, err)

		foundToken, err := repo.GetByToken(context.Background(), token.TokenHash)
		assert.NoError(test, err)
		assert.NotNil(test, foundToken)
		assert.Equal(test, commonToken.AccessTokenType, foundToken.Type)
		assert.True(test, foundToken.Revoked)
		assert.Equal(test, issueAt, token.IssuedAt)
		assert.Equal(test, expiresAt, token.ExpiresAt)
	})
	test.Run("Update_User_Not_Found", func(test *testing.T) {
		mongoServer, client, error := mock.SetupMockMongoServerAndClient(test)
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		repo := NewTokenRepository(client)

		token := model.NewToken("test_token_hash", "test_token")

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
		token := model.NewToken("test_token_hash", "test_token")

		_, err = repo.InsertToken(context.Background(), token)
		assert.NoError(test, err)

		err = repo.Remove(context.Background(), token)
		assert.NoError(test, err)

		foundToken, err := repo.GetByUserIDAndTokenType(context.Background(), token.UserID, token.Type)
		assert.Error(test, err)
		assert.Equal(test, "Error finding token by user_id and token_hash: mongo: no documents in result", err.Error())
		assert.Nil(test, foundToken)
	})
}

package mongo

import (
	"context"
	"fmt"
	"testing"
	"time"

	commonToken "github.com/quadev-ltd/qd-common/pkg/token"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
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

		user.ID = id
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
		user.AuthTypes[0] = model.FirebaseAuthType

		insertedID, err := repo.InsertUser(context.Background(), user)
		assert.NoError(test, err)
		id, ok := insertedID.(primitive.ObjectID)
		assert.True(test, ok)
		assert.NotNil(test, id)

		newHash := "new-hash"
		newSalt := "new-salt"
		user.PasswordHash = newHash
		user.PasswordSalt = newSalt
		user.AuthTypes = append(user.AuthTypes, model.PasswordAuthType)

		user.ID = id

		err = repo.UpdatePassword(context.Background(), user)
		assert.NoError(test, err)

		foundUser, err := repo.GetByEmail(context.Background(), user.Email)
		assert.NoError(test, err)
		assert.NotNil(test, foundUser)
		assert.Equal(test, foundUser.PasswordHash, newHash)
		assert.Equal(test, foundUser.PasswordSalt, newSalt)
		assert.True(test, model.ContainsAuthType(foundUser.AuthTypes, model.PasswordAuthType))
		assert.True(test, model.ContainsAuthType(foundUser.AuthTypes, model.FirebaseAuthType))
	})

	test.Run("UpdateAuthTypes_Success", func(test *testing.T) {
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

		user.AuthTypes[0] = model.FirebaseAuthType

		user.ID = id

		err = repo.UpdateAuthTypes(context.Background(), user)
		assert.NoError(test, err)

		foundUser, err := repo.GetByEmail(context.Background(), user.Email)
		assert.NoError(test, err)
		assert.NotNil(test, foundUser)
		assert.False(test, model.ContainsAuthType(foundUser.AuthTypes, model.PasswordAuthType))
		assert.True(test, model.ContainsAuthType(foundUser.AuthTypes, model.FirebaseAuthType))
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
		user.ID = id

		updatedUser, err := repo.UpdateProfileDetails(context.Background(), user)

		assert.NoError(test, err)

		foundUser, err := repo.GetByEmail(context.Background(), user.Email)
		assert.NoError(test, err)
		assert.NotNil(test, foundUser)
		assert.Equal(test, updatedUser.DateOfBirth.Unix(), newBirthDay.Unix())
		assert.Equal(test, updatedUser.FirstName, newFirstName)
		assert.Equal(test, updatedUser.LastName, newLastName)
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
		updatedUser, err := repo.UpdateProfileDetails(context.Background(), user)

		assert.Error(test, err)
		assert.Nil(test, updatedUser)
		assert.Equal(test, "No account was found", err.Error())
	})

	test.Run("RemoveByUserIdAndTokenType_AllSameUser_Succcess", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		if err != nil {
			test.Fatal(err)
		}
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		tokenRepo := NewTokenRepository(client)

		// Create a user for the tokens
		userID := primitive.NewObjectID()

		// Create tokens for the user
		tokenType := commonToken.EmailVerificationTokenType
		tokens := make([]*model.Token, 4)
		for i := range tokens {
			tokens[i] = &model.Token{
				UserID:    userID,
				TokenHash: "token-hash",
				Type:      tokenType,
			}
			if i == 3 {
				tokens[i].Type = commonToken.ResetPasswordTokenType
			}
			_, err = tokenRepo.InsertToken(context.Background(), tokens[i])
			assert.NoError(test, err)
		}

		// Remove tokens by UserID and TokenType
		err = tokenRepo.RemoveAllByUserIDAndTokenType(context.Background(), userID, tokenType)
		assert.NoError(test, err)

		// Assert that only the last token with a different type remains
		count, err := tokenRepo.getCollection().CountDocuments(context.Background(), bson.M{"userID": userID})
		assert.NoError(test, err)
		assert.Equal(test, int64(1), count, "There should only be one token left after removal")
	})

	test.Run("RemoveByUserIdAndTokenType_DifferentUSers_Successs", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		if err != nil {
			test.Fatal(err)
		}
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		tokenRepo := NewTokenRepository(client)

		// Create a user for the tokens
		user1ID := primitive.NewObjectID()
		user2ID := primitive.NewObjectID()

		// Create tokens for the user
		tokenType := commonToken.EmailVerificationTokenType
		tokens := make([]*model.Token, 5)
		for i := range tokens {
			tokens[i] = &model.Token{
				UserID:    user1ID,
				TokenHash: "token-hash",
				Type:      tokenType,
			}
			if i == 0 {
				tokens[i].Type = commonToken.ResetPasswordTokenType
			}
			if i == 3 {
				tokens[i].UserID = user2ID
			}
			if i == 4 {
				tokens[i].UserID = user2ID
				tokens[i].Type = commonToken.ResetPasswordTokenType
			}
			fmt.Println("Tokens:::", tokens[i])
			_, err = tokenRepo.InsertToken(context.Background(), tokens[i])
			assert.NoError(test, err)
		}

		// Remove tokens by UserID and TokenType
		err = tokenRepo.RemoveAllByUserIDAndTokenType(context.Background(), user1ID, tokenType)
		assert.NoError(test, err)

		// Assert that only the last token with a different type remains
		count, err := tokenRepo.getCollection().CountDocuments(context.Background(), bson.M{"userID": user1ID})
		assert.NoError(test, err)
		assert.Equal(test, int64(1), count, "There should only be one tokens left after removal")
		count, err = tokenRepo.getCollection().CountDocuments(context.Background(), bson.M{"userID": user2ID})
		assert.NoError(test, err)
		assert.Equal(test, int64(2), count, "There should only be two tokens left after removal")
	})

	test.Run("DeleteByUserID_Success", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		if err != nil {
			test.Fatal(err)
		}
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		repo := NewUserRepository(client)

		// Insert a user to delete
		user := model.NewUser()
		insertedID, err := repo.InsertUser(context.Background(), user)
		assert.NoError(test, err)

		id, ok := insertedID.(primitive.ObjectID)
		assert.True(test, ok)
		assert.NotNil(test, id)

		// Delete the user
		err = repo.DeleteByUserID(context.Background(), id)
		assert.NoError(test, err)

		// Verify user no longer exists
		foundUser, err := repo.GetByUserID(context.Background(), id)
		assert.Nil(test, foundUser)
		assert.Error(test, err)
		assert.Contains(test, err.Error(), "Error finding user by verification token")
	})

	test.Run("DeleteByUserID_User_Not_Found", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		if err != nil {
			test.Fatal(err)
		}
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		repo := NewUserRepository(client)

		// Attempt to delete a user that doesn't exist
		id := primitive.NewObjectID()
		err = repo.DeleteByUserID(context.Background(), id)

		// The DeleteOne method in MongoDB does not return an error if no document is found.
		// So this err should be nil. We just confirm that a user is indeed not found afterward.
		assert.NoError(test, err)

		foundUser, err := repo.GetByUserID(context.Background(), id)
		assert.Nil(test, foundUser)
		assert.Error(test, err)
		assert.Contains(test, err.Error(), "Error finding user by verification token")
	})

	test.Run("GetByEmail_DefaultHasPaidFeatures", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		if err != nil {
			test.Fatal(err)
		}
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		repo := NewUserRepository(client)

		// Create a user without HasPaidFeatures field
		user := model.NewUser()
		insertedID, err := repo.InsertUser(context.Background(), user)
		assert.NoError(test, err)
		id, ok := insertedID.(primitive.ObjectID)
		assert.True(test, ok)
		assert.NotNil(test, id)

		// Update the document to remove HasPaidFeatures field
		collection := client.Database("test").Collection("users")
		_, err = collection.UpdateOne(
			context.Background(),
			bson.M{"_id": id},
			bson.M{"$unset": bson.M{"hasPaidFeatures": ""}},
		)
		assert.NoError(test, err)

		// Get the user and verify HasPaidFeatures is false
		foundUser, err := repo.GetByEmail(context.Background(), user.Email)
		assert.NoError(test, err)
		assert.NotNil(test, foundUser)
		assert.False(test, foundUser.HasPaidFeatures, "HasPaidFeatures should default to false when not present in document")
	})

	test.Run("GetByEmail_HasPaidFeaturesTrue", func(test *testing.T) {
		mongoServer, client, err := mock.SetupMockMongoServerAndClient(test)
		if err != nil {
			test.Fatal(err)
		}
		defer client.Disconnect(context.Background())
		defer mongoServer.Stop()

		repo := NewUserRepository(client)

		// Create a user with HasPaidFeatures set to true
		user := model.NewUser()
		user.HasPaidFeatures = true
		insertedID, err := repo.InsertUser(context.Background(), user)
		assert.NoError(test, err)
		id, ok := insertedID.(primitive.ObjectID)
		assert.True(test, ok)
		assert.NotNil(test, id)

		// Get the user and verify HasPaidFeatures is true
		foundUser, err := repo.GetByEmail(context.Background(), user.Email)
		assert.NoError(test, err)
		assert.NotNil(test, foundUser)
		assert.True(test, foundUser.HasPaidFeatures, "HasPaidFeatures should be true when set in document")
	})

}

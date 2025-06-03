package service

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"firebase.google.com/go/auth"
	"github.com/go-playground/validator/v10"
	"github.com/golang/mock/gomock"
	"github.com/quadev-ltd/qd-common/pb/gen/go/pb_authentication"
	commonJWT "github.com/quadev-ltd/qd-common/pkg/jwt"
	"github.com/quadev-ltd/qd-common/pkg/log"
	loggerMock "github.com/quadev-ltd/qd-common/pkg/log/mock"
	commonToken "github.com/quadev-ltd/qd-common/pkg/token"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"google.golang.org/protobuf/types/known/timestamppb"

	firebaseMock "qd-authentication-api/internal/firebase/mock"
	"qd-authentication-api/internal/model"
	repositoryMock "qd-authentication-api/internal/repository/mock"
	serviceMock "qd-authentication-api/internal/service/mock"
)

const (
	testEmail     = "test@example.com"
	testPassword  = "Password123!"
	testFirstName = "John"
	testLastName  = "Doe"
	invalidEmail  = "invalid-email"
)

var (
	testDateOfBirth         = time.Time{}
	userID                  = primitive.NewObjectID()
	errExample              = errors.New("test-error")
	refreshTokenValue       = "refresh-token"
	resetPasswordTokenValue = "reset-password-token"
	verificationTokenValue  = "MjAyNDAzMDlfClvE5pSXfIepywonOEgHvOEbWFj0_wSrg4feaV9SYw=="
	verificationTokenHash   = "$2a$10$lIVkFYORGPHIr5DgPwM3yO2uOkumFJ.RWF3IDHqp0xnqqlGjQ1cb6"
	testTokenValue          = "test-token-hash"
	testTokenHashValue      = "test-token-hash"
	newRefreshTokenValue    = "test_token_example"
	authTokenClaims         = &commonJWT.TokenClaims{
		Email:  testEmail,
		Type:   commonToken.AuthTokenType,
		Expiry: time.Now().Add(5 * time.Minute),
	}
	refreshTokenClaims = &commonJWT.TokenClaims{
		Email:  testEmail,
		Type:   commonToken.RefreshTokenType,
		Expiry: time.Now().Add(5 * time.Minute),
	}
)

type AuthServiceMockedParams struct {
	MockUserRepo        repositoryMock.MockUserRepositoryer
	MockFirebaseService firebaseMock.MockAuthServicer
	MockEmailService    serviceMock.MockEmailServicer
	MockLogger          *loggerMock.MockLoggerer
	UserService         UserServicer
	Controller          *gomock.Controller
	Ctx                 context.Context
}

func createUserService(test *testing.T) *AuthServiceMockedParams {
	controller := gomock.NewController(test)
	mockUserRepo := repositoryMock.NewMockUserRepositoryer(controller)
	mockEmailService := serviceMock.NewMockEmailServicer(controller)
	mockFirebaseService := firebaseMock.NewMockAuthServicer(controller)
	mockLogger := loggerMock.NewMockLoggerer(controller)
	userService := NewUserService(
		mockEmailService,
		mockFirebaseService,
		mockUserRepo,
	)
	ctx := context.WithValue(context.Background(), log.LoggerKey, mockLogger)

	return &AuthServiceMockedParams{
		*mockUserRepo,
		*mockFirebaseService,
		*mockEmailService,
		mockLogger,
		userService,
		controller,
		ctx,
	}
}

func TestUserService(test *testing.T) {
	// Register
	test.Run("Register_Success", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(false, nil)
		mocks.MockUserRepo.EXPECT().InsertUser(gomock.Any(), gomock.Any()).Return(userID, nil)
		createdUser, err := mocks.UserService.Register(
			mocks.Ctx,
			testEmail,
			testPassword,
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)
		assert.NoError(test, err)
		assert.Equal(test, testEmail, createdUser.Email)
		assert.Equal(test, testFirstName, createdUser.FirstName)
		assert.Equal(test, testLastName, createdUser.LastName)
		assert.Equal(test, userID, createdUser.ID)
		assert.Equal(test, testDateOfBirth.Unix(), createdUser.DateOfBirth.Unix())

	})

	test.Run("Register_Email_Uniqueness", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(true, nil)

		createdUser, err := mocks.UserService.Register(
			mocks.Ctx,
			testEmail,
			testPassword,
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)

		assert.Nil(test, createdUser)
		assert.Error(test, err)
		assert.Equal(test, (&model.EmailInUseError{Email: testEmail}).Error(), err.Error())
	})
	test.Run("Register_ExistsFail_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), invalidEmail).Return(false, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, fmt.Sprintf("Error checking user existence by email: %v", invalidEmail))

		createdUser, err := mocks.UserService.Register(
			mocks.Ctx,
			invalidEmail,
			testPassword,
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)

		assert.Nil(test, createdUser)
		assert.Error(test, err)
		assert.Equal(test, fmt.Sprintf("Error checking user existence by email: %v", invalidEmail), err.Error())
	})
	test.Run("Register_Invalid_Email", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), invalidEmail).Return(false, nil)

		createdUser, err := mocks.UserService.Register(
			mocks.Ctx,
			invalidEmail,
			testPassword,
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)

		assert.Nil(test, createdUser)
		assert.Error(test, err)
		var validationErrs validator.ValidationErrors
		assert.ErrorAs(test, err, &validationErrs)
		assert.Contains(test, err.Error(), "Email")
	})
	test.Run("Register_Invalid_DOB", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()
		invalidDateOfBirth := time.Now().Add(2 * time.Hour)

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(false, nil)

		createdUser, err := mocks.UserService.Register(
			mocks.Ctx,
			testEmail,
			testPassword,
			testFirstName,
			testLastName,
			&invalidDateOfBirth,
		)

		assert.Nil(test, createdUser)
		assert.Error(test, err)
		var validationErrs validator.ValidationErrors
		assert.ErrorAs(test, err, &validationErrs)
		assert.Contains(test, err.Error(), "DateOfBirth")
	})
	test.Run("Register_Password_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(false, nil)

		createdUser, err := mocks.UserService.Register(
			mocks.Ctx,
			testEmail,
			"testPassword",
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)
		assert.Nil(test, createdUser)
		assert.Error(test, err)
		assert.IsType(test, &NoComplexPasswordError{}, err)
		assert.Equal(test, "Password does not meet complexity requirements", err.Error())
	})

	test.Run("Register_Fail_Parsing_Inserted_ID_error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(false, nil)
		mocks.MockUserRepo.EXPECT().InsertUser(gomock.Any(), gomock.Any()).Return("", nil)

		createdUser, err := mocks.UserService.Register(
			mocks.Ctx,
			testEmail,
			testPassword,
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)
		assert.Nil(test, createdUser)
		assert.Error(test, err)
		assert.Equal(test, "InsertedID is not of type primitive.ObjectID", err.Error())
	})

	// 	// Verify
	test.Run("VerifyEmail_Verify_Success", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		testToken := model.NewToken(testTokenHashValue)

		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)
		mocks.MockUserRepo.EXPECT().UpdateStatus(gomock.Any(), testUser).Return(nil)
		mocks.MockEmailService.EXPECT().SendVerificationSuccessEmail(gomock.Any(), testUser.Email, testUser.FirstName)

		// Test successful verification
		user, err := mocks.UserService.VerifyEmail(mocks.Ctx, testToken)

		assert.NoError(test, err)
		assert.Equal(test, model.AccountStatusVerified, testUser.AccountStatus)
		assert.Equal(test, testUser, user)
	})

	test.Run("VerifyEmail_Get_User_By_ID_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testToken := model.NewToken(testTokenHashValue)

		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error getting user by ID")

		// Test Verify
		user, resultError := mocks.UserService.VerifyEmail(mocks.Ctx, testToken)

		assert.Error(test, resultError)
		assert.NotNil(test, resultError)
		assert.Equal(test, "invalid_token", resultError.Error())
		assert.Nil(test, user)
	})
	test.Run("Invalid_Token_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testToken := model.NewToken(testTokenHashValue)
		testUser := model.NewUser()
		testUser.AccountStatus = model.AccountStatusVerified

		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)

		// Test Verify
		user, resultError := mocks.UserService.VerifyEmail(mocks.Ctx, testToken)

		assert.Error(test, resultError)
		assert.IsType(test, &Error{}, resultError)
		assert.Equal(test, "email_already_verified", resultError.Error())
		assert.Nil(test, user)
	})
	test.Run("VerifyEmail_Update_error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testToken := model.NewToken(testTokenHashValue)
		testUser := model.NewUser()

		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)
		mocks.MockUserRepo.EXPECT().UpdateStatus(gomock.Any(), testUser).Return(errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error updating user status")
		// Act
		user, resultError := mocks.UserService.VerifyEmail(mocks.Ctx, testToken)

		// Assert
		assert.Error(test, resultError)
		assert.Equal(test, "Error updating user status", resultError.Error())
		assert.Nil(test, user)
	})

	// Authenticate
	test.Run("Authenticate_GetByEmail_error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		errorMessage := "Database error"
		errExample := errors.New(errorMessage)

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, fmt.Sprintf("Error getting user by email: %v", testEmail))

		// Test Authenticate
		user, err := mocks.UserService.Authenticate(mocks.Ctx, testEmail, "password")

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error getting user by email", err.Error())
		assert.Nil(test, user)
	})
	test.Run("Authenticate_User_Not_Found", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		email := "test@example.com"
		password := "password"

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), email).Return(nil, nil)

		// Test Authenticate
		user, err := mocks.UserService.Authenticate(mocks.Ctx, email, password)

		assert.Error(test, err)
		assert.Equal(test, "Wrong Email", err.Error())
		assert.Nil(test, user)
	})

	test.Run("Authenticate_Invalid_AuthType", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		email := "test@example.com"

		testUser := &model.User{
			Email:            email,
			FirstName:        "Test",
			LastName:         "User",
			DateOfBirth:      time.Now(),
			RegistrationDate: time.Now(),
			LastLoginDate:    time.Now(),
			AuthTypes:        []model.AuthenticationType{model.FirebaseAuthType},
		}

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), email).Return(testUser, nil)

		// Test Authenticate
		resultUser, resultError := mocks.UserService.Authenticate(mocks.Ctx, email, "password")

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, resultUser)
		assert.Equal(test, "Wrong AuthType", resultError.Error())
	})

	test.Run("Authenticate_Invalid_Password", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		email := "test@example.com"

		testUser := model.NewUser()
		invalidPassword := "invalidpassword"

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), email).Return(testUser, nil)

		// Test Authenticate
		resultUser, resultError := mocks.UserService.Authenticate(mocks.Ctx, email, invalidPassword)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, resultUser)
		assert.Equal(test, "Wrong Password", resultError.Error())
	})

	test.Run("Authenticate_Authenticate_Success", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		testUser.PasswordHash = "$2a$10$b4R.rxNHsELRW/JaqI1kS.CXO.xVamz.rwFXxchWD2pdKhKzZp94u"
		testUser.PasswordSalt = "7jQQnlalvK1E0iDzugF18ewa1Auf7R71Dr6OWnJbZbI="

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)
		mocks.MockEmailService.EXPECT().SendAuthenticationSuccessEmail(
			gomock.Any(),
			testUser.Email,
			testUser.FirstName,
		).Return(nil)

		// Act
		resultUser, resultError := mocks.UserService.Authenticate(mocks.Ctx, testEmail, testPassword)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, resultUser)
		assert.Equal(test, testUser.PasswordHash, resultUser.PasswordHash)
		assert.Equal(test, testUser.PasswordSalt, resultUser.PasswordSalt)
		assert.Equal(test, testUser.FirstName, resultUser.FirstName)
		assert.Equal(test, testUser.LastName, resultUser.LastName)
		assert.Equal(test, testUser.Email, resultUser.Email)
	})

	test.Run("AuthenticateWithFirebase_UserNotExist_Success", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewFirebaseUser()
		idToken := "id-token"
		userID = primitive.NewObjectID()

		token := &auth.Token{
			Claims: map[string]interface{}{
				"email": testUser.Email,
			},
		}

		mocks.MockFirebaseService.EXPECT().VerifyIDToken(
			gomock.Any(),
			idToken,
		).Return(
			token,
			nil,
		)
		mocks.MockUserRepo.EXPECT().ExistsByEmail(
			gomock.Any(),
			testUser.Email,
		).Return(
			false,
			nil,
		)
		mocks.MockUserRepo.EXPECT().InsertUser(
			gomock.Any(),
			gomock.Any(),
		).Return(
			userID,
			nil,
		)
		mocks.MockEmailService.EXPECT().SendAuthenticationSuccessEmail(
			gomock.Any(),
			testUser.Email,
			testUser.FirstName,
		).Return(nil)

		// Act
		resultUser, resultError := mocks.UserService.AuthenticateWithFirebase(
			mocks.Ctx,
			idToken,
			testUser.Email,
			testUser.FirstName,
			testUser.LastName,
		)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, resultUser)
		assert.Equal(test, testUser.Email, resultUser.Email)
		assert.Equal(test, testUser.FirstName, resultUser.FirstName)
		assert.Equal(test, testUser.LastName, resultUser.LastName)
		assert.NotEqual(test, testUser.LastLoginDate.UTC().String(), resultUser.LastLoginDate.UTC().String())
	})

	test.Run("AuthenticateWithFirebase_UserNotExist_InsertError", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewFirebaseUser()
		idToken := "id-token"
		userID = primitive.NewObjectID()

		token := &auth.Token{
			Claims: map[string]interface{}{
				"email": testUser.Email,
			},
		}

		mocks.MockFirebaseService.EXPECT().VerifyIDToken(
			gomock.Any(),
			idToken,
		).Return(
			token,
			nil,
		)
		mocks.MockUserRepo.EXPECT().ExistsByEmail(
			gomock.Any(),
			testUser.Email,
		).Return(
			false,
			nil,
		)
		mocks.MockUserRepo.EXPECT().InsertUser(
			gomock.Any(),
			gomock.Any(),
		).Return(
			nil,
			errExample,
		)
		mocks.MockLogger.EXPECT().Error(
			errExample,
			"Error inserting user in DB",
		)

		// Act
		resultUser, resultError := mocks.UserService.AuthenticateWithFirebase(
			mocks.Ctx,
			idToken,
			testUser.Email,
			testUser.FirstName,
			testUser.LastName,
		)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, resultUser)
		assert.EqualError(test, resultError, "Error storing user")
	})

	test.Run("AuthenticateWithFirebase_UserNotExist_WrongObjectID_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewFirebaseUser()
		idToken := "id-token"
		userID = primitive.NewObjectID()

		token := &auth.Token{
			Claims: map[string]interface{}{
				"email": testUser.Email,
			},
		}

		mocks.MockFirebaseService.EXPECT().VerifyIDToken(
			gomock.Any(),
			idToken,
		).Return(
			token,
			nil,
		)
		mocks.MockUserRepo.EXPECT().ExistsByEmail(
			gomock.Any(),
			testUser.Email,
		).Return(
			false,
			nil,
		)
		mocks.MockUserRepo.EXPECT().InsertUser(
			gomock.Any(),
			gomock.Any(),
		).Return(
			"nil",
			nil,
		)

		// Act
		resultUser, resultError := mocks.UserService.AuthenticateWithFirebase(
			mocks.Ctx,
			idToken,
			testUser.Email,
			testUser.FirstName,
			testUser.LastName,
		)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, resultUser)
		assert.EqualError(test, resultError, "InsertedID is not of type primitive.ObjectID")
	})

	test.Run("AuthenticateWithFirebase_UserNotExist_Validation_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewFirebaseUser()
		testUser.Email = "invalid email"
		idToken := "id-token"
		userID = primitive.NewObjectID()

		token := &auth.Token{
			Claims: map[string]interface{}{
				"email": testUser.Email,
			},
		}

		mocks.MockFirebaseService.EXPECT().VerifyIDToken(
			gomock.Any(),
			idToken,
		).Return(
			token,
			nil,
		)
		mocks.MockUserRepo.EXPECT().ExistsByEmail(
			gomock.Any(),
			testUser.Email,
		).Return(
			false,
			nil,
		)

		// Act
		resultUser, resultError := mocks.UserService.AuthenticateWithFirebase(
			mocks.Ctx,
			idToken,
			testUser.Email,
			testUser.FirstName,
			testUser.LastName,
		)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, resultUser)
		assert.EqualError(test, resultError, "Key: 'User.Email' Error:Field validation for 'Email' failed on the 'email' tag")
	})

	test.Run("AuthenticateWithFirebase_PasswordUserExist_Success", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		idToken := "id-token"
		userID = primitive.NewObjectID()

		token := &auth.Token{
			Claims: map[string]interface{}{
				"email": testUser.Email,
			},
		}

		mocks.MockFirebaseService.EXPECT().VerifyIDToken(
			gomock.Any(),
			idToken,
		).Return(
			token,
			nil,
		)
		mocks.MockUserRepo.EXPECT().ExistsByEmail(
			gomock.Any(),
			testUser.Email,
		).Return(
			true,
			nil,
		)
		mocks.MockUserRepo.EXPECT().GetByEmail(
			gomock.Any(),
			testUser.Email,
		).Return(
			testUser,
			nil,
		)
		mocks.MockUserRepo.EXPECT().UpdateAuthTypes(
			gomock.Any(),
			gomock.Eq(testUser),
		).Return(
			nil,
		)
		mocks.MockUserRepo.EXPECT().UpdateStatus(
			gomock.Any(),
			gomock.Eq(testUser),
		).Return(
			nil,
		)
		mocks.MockEmailService.EXPECT().SendAuthenticationSuccessEmail(
			gomock.Any(),
			testUser.Email,
			testUser.FirstName,
		).Return(nil)

		// Act
		resultUser, resultError := mocks.UserService.AuthenticateWithFirebase(
			mocks.Ctx,
			idToken,
			testUser.Email,
			testUser.FirstName,
			testUser.LastName,
		)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, resultUser)
		assert.Equal(test, testUser.Email, resultUser.Email)
		assert.Equal(test, testUser.FirstName, resultUser.FirstName)
		assert.Equal(test, testUser.LastName, resultUser.LastName)
		assert.Equal(test, testUser.LastLoginDate.UTC().String(), resultUser.LastLoginDate.UTC().String())
	})

	test.Run("AuthenticateWithFirebase_PasswordUserExistVerifiedUser_Success", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		testUser.AccountStatus = model.AccountStatusVerified
		idToken := "id-token"
		userID = primitive.NewObjectID()

		token := &auth.Token{
			Claims: map[string]interface{}{
				"email": testUser.Email,
			},
		}

		mocks.MockFirebaseService.EXPECT().VerifyIDToken(
			gomock.Any(),
			idToken,
		).Return(
			token,
			nil,
		)
		mocks.MockUserRepo.EXPECT().ExistsByEmail(
			gomock.Any(),
			testUser.Email,
		).Return(
			true,
			nil,
		)
		mocks.MockUserRepo.EXPECT().GetByEmail(
			gomock.Any(),
			testUser.Email,
		).Return(
			testUser,
			nil,
		)
		mocks.MockUserRepo.EXPECT().UpdateAuthTypes(
			gomock.Any(),
			gomock.Eq(testUser),
		).Return(
			nil,
		)
		mocks.MockEmailService.EXPECT().SendAuthenticationSuccessEmail(
			gomock.Any(),
			testUser.Email,
			testUser.FirstName,
		).Return(nil)

		// Act
		resultUser, resultError := mocks.UserService.AuthenticateWithFirebase(
			mocks.Ctx,
			idToken,
			testUser.Email,
			testUser.FirstName,
			testUser.LastName,
		)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, resultUser)
		assert.Equal(test, testUser.Email, resultUser.Email)
		assert.Equal(test, testUser.FirstName, resultUser.FirstName)
		assert.Equal(test, testUser.LastName, resultUser.LastName)
		assert.Equal(test, testUser.LastLoginDate.UTC().String(), resultUser.LastLoginDate.UTC().String())
	})

	test.Run("AuthenticateWithFirebase_UpdateStatus_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		idToken := "id-token"
		userID = primitive.NewObjectID()

		token := &auth.Token{
			Claims: map[string]interface{}{
				"email": testUser.Email,
			},
		}

		mocks.MockFirebaseService.EXPECT().VerifyIDToken(
			gomock.Any(),
			idToken,
		).Return(
			token,
			nil,
		)
		mocks.MockUserRepo.EXPECT().ExistsByEmail(
			gomock.Any(),
			testUser.Email,
		).Return(
			true,
			nil,
		)
		mocks.MockUserRepo.EXPECT().GetByEmail(
			gomock.Any(),
			testUser.Email,
		).Return(
			testUser,
			nil,
		)
		mocks.MockUserRepo.EXPECT().UpdateAuthTypes(
			gomock.Any(),
			gomock.Eq(testUser),
		).Return(
			nil,
		)
		mocks.MockUserRepo.EXPECT().UpdateStatus(
			gomock.Any(),
			gomock.Eq(testUser),
		).Return(
			errExample,
		)
		mocks.MockLogger.EXPECT().Error(errExample, fmt.Sprintf("Error updating user %s status", testUser.Email))

		// Act
		resultUser, resultError := mocks.UserService.AuthenticateWithFirebase(
			mocks.Ctx,
			idToken,
			testUser.Email,
			testUser.FirstName,
			testUser.LastName,
		)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, resultUser)
		assert.EqualError(test, resultError, "Error updating user status")
	})

	test.Run("AuthenticateWithFirebase_PasswordUserExist_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		idToken := "id-token"
		userID = primitive.NewObjectID()

		token := &auth.Token{
			Claims: map[string]interface{}{
				"email": testUser.Email,
			},
		}

		mocks.MockFirebaseService.EXPECT().VerifyIDToken(
			gomock.Any(),
			idToken,
		).Return(
			token,
			nil,
		)
		mocks.MockUserRepo.EXPECT().ExistsByEmail(
			gomock.Any(),
			testUser.Email,
		).Return(
			true,
			nil,
		)
		mocks.MockUserRepo.EXPECT().GetByEmail(
			gomock.Any(),
			testUser.Email,
		).Return(
			testUser,
			nil,
		)
		mocks.MockUserRepo.EXPECT().UpdateAuthTypes(
			gomock.Any(),
			testUser,
		).Return(
			errExample,
		)
		mocks.MockLogger.EXPECT().Error(errExample, fmt.Sprintf("Error updating user %s auth type", testUser.Email))

		// Act
		resultUser, resultError := mocks.UserService.AuthenticateWithFirebase(
			mocks.Ctx,
			idToken,
			testUser.Email,
			testUser.FirstName,
			testUser.LastName,
		)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, resultUser)
		assert.EqualError(test, resultError, "Error updating user auth type")
	})

	test.Run("AuthenticateWithFirebase_FirebaseUserExist_Success", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewFirebaseUser()
		idToken := "id-token"
		userID = primitive.NewObjectID()

		token := &auth.Token{
			Claims: map[string]interface{}{
				"email": testUser.Email,
			},
		}

		mocks.MockFirebaseService.EXPECT().VerifyIDToken(
			gomock.Any(),
			idToken,
		).Return(
			token,
			nil,
		)
		mocks.MockUserRepo.EXPECT().ExistsByEmail(
			gomock.Any(),
			testUser.Email,
		).Return(
			true,
			nil,
		)
		mocks.MockUserRepo.EXPECT().GetByEmail(
			gomock.Any(),
			testUser.Email,
		).Return(
			testUser,
			nil,
		)
		mocks.MockEmailService.EXPECT().SendAuthenticationSuccessEmail(
			gomock.Any(),
			testUser.Email,
			testUser.FirstName,
		).Return(nil)

		// Act
		resultUser, resultError := mocks.UserService.AuthenticateWithFirebase(
			mocks.Ctx,
			idToken,
			testUser.Email,
			testUser.FirstName,
			testUser.LastName,
		)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, resultUser)
		assert.Equal(test, testUser.Email, resultUser.Email)
		assert.Equal(test, testUser.FirstName, resultUser.FirstName)
		assert.Equal(test, testUser.LastName, resultUser.LastName)
		assert.Equal(test, testUser.LastLoginDate.UTC().String(), resultUser.LastLoginDate.UTC().String())
	})

	test.Run("AuthenticateWithFirebase_UserExistsGetUser_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewFirebaseUser()
		testUser.Email = "invalid-email"
		idToken := "id-token"
		userID = primitive.NewObjectID()

		token := &auth.Token{
			Claims: map[string]interface{}{
				"email": testUser.Email,
			},
		}

		mocks.MockFirebaseService.EXPECT().VerifyIDToken(
			gomock.Any(),
			idToken,
		).Return(
			token,
			nil,
		)
		mocks.MockUserRepo.EXPECT().ExistsByEmail(
			gomock.Any(),
			testUser.Email,
		).Return(
			true,
			nil,
		)
		mocks.MockUserRepo.EXPECT().GetByEmail(
			gomock.Any(),
			testUser.Email,
		).Return(
			nil,
			errExample,
		)
		mocks.MockLogger.EXPECT().Error(
			errExample,
			"Error getting user by email invalid-email",
		)

		// Act
		resultUser, resultError := mocks.UserService.AuthenticateWithFirebase(
			mocks.Ctx,
			idToken,
			testUser.Email,
			testUser.FirstName,
			testUser.LastName,
		)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, resultUser)
		assert.EqualError(test, resultError, "Error getting user by email")
	})

	// // ResendEmailVerification
	test.Run("ResendEmailVerification_GetByEmail_AlreadyVerified", func(test *testing.T) {
		// Arrange

		testUser := model.NewUser()
		testUser.AccountStatus = model.AccountStatusVerified
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		// Act
		err := mocks.UserService.ResendEmailVerification(mocks.Ctx, testUser, testTokenValue)

		// Assert
		assert.Error(test, err)
		assert.IsType(test, &Error{}, err)
		assert.Contains(test, err.Error(), "email_already_verified")
	})

	test.Run("ResendEmailVerification_SendEmail_Error", func(test *testing.T) {
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		errExample := errors.New("Email service error")

		mocks.MockEmailService.EXPECT().SendVerificationEmail(
			mocks.Ctx,
			testEmail,
			testUser.FirstName,
			testUser.ID.Hex(),
			gomock.Any(),
		).Return(errExample)

		// Act
		err := mocks.UserService.ResendEmailVerification(mocks.Ctx, testUser, testTokenValue)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error sending verification email: Email service error", err.Error())
	})

	test.Run("ResendEmailVerification_Success", func(test *testing.T) {
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()

		mocks.MockEmailService.EXPECT().SendVerificationEmail(
			mocks.Ctx,
			testEmail,
			testUser.FirstName,
			testUser.ID.Hex(),
			testTokenHashValue,
		).Return(nil)

		// Act
		err := mocks.UserService.ResendEmailVerification(mocks.Ctx, testUser, testTokenValue)

		// Assert
		assert.NoError(test, err)
	})

	// GetUserProfile
	test.Run("GetUserProfile_Success", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()
		testUser := model.NewUser()

		mocks.MockUserRepo.EXPECT().GetByUserID(
			gomock.Any(),
			testUser.ID,
		).Return(testUser, nil)

		// Test RefreshToken
		profileResult, resultError := mocks.UserService.GetUserProfile(
			mocks.Ctx,
			testUser.ID.Hex(),
		)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, profileResult)
		assert.True(test, reflect.DeepEqual(profileResult, testUser))
	})

	test.Run("GetUserProfile_GetUser_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()
		testUser := model.NewUser()
		mockedError := errors.New("test-error")

		mocks.MockUserRepo.EXPECT().GetByUserID(
			gomock.Any(),
			testUser.ID,
		).Return(nil, mockedError)
		mocks.MockLogger.EXPECT().Error(mockedError, "Error getting user by ID")

		// Test RefreshToken
		profileResult, resultError := mocks.UserService.GetUserProfile(
			mocks.Ctx,
			testUser.ID.Hex(),
		)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, profileResult)
		assert.EqualError(test, resultError, "Error getting user by ID")
	})

	// UpdateUserProfile
	test.Run("UpdateUserProfile_Success", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()
		testUser := model.NewUser()
		profileDetails := &pb_authentication.UpdateUserProfileRequest{
			FirstName:   testUser.FirstName,
			LastName:    testUser.LastName,
			DateOfBirth: timestamppb.New(testUser.DateOfBirth),
		}
		createdProfileUser := &model.User{
			ID:          testUser.ID,
			FirstName:   testUser.FirstName,
			LastName:    testUser.LastName,
			DateOfBirth: testUser.DateOfBirth.UTC(),
		}

		mocks.MockUserRepo.EXPECT().UpdateProfileDetails(
			gomock.Any(),
			gomock.Eq(createdProfileUser),
		).Return(testUser, nil)

		// Test RefreshToken
		updateResponse, resultError := mocks.UserService.UpdateProfileDetails(
			mocks.Ctx,
			testUser.ID.Hex(),
			profileDetails,
		)

		// Assert
		assert.NoError(test, resultError)
		assert.Equal(test, testUser.ID.Hex(), updateResponse.ID.Hex())
		assert.Equal(test, testUser.FirstName, updateResponse.FirstName)
		assert.Equal(test, testUser.LastName, updateResponse.LastName)
		assert.Equal(test, testUser.DateOfBirth.Unix(), updateResponse.DateOfBirth.Unix())
		assert.Equal(test, testUser.Email, updateResponse.Email)
		assert.Equal(test, testUser.AccountStatus, updateResponse.AccountStatus)
	})

	test.Run("UpdateUserProfile_Update_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()
		testUser := model.NewUser()
		profileDetails := &pb_authentication.UpdateUserProfileRequest{
			FirstName:   testUser.FirstName,
			LastName:    testUser.LastName,
			DateOfBirth: timestamppb.New(testUser.DateOfBirth),
		}
		createdProfileUser := &model.User{
			ID:          testUser.ID,
			FirstName:   testUser.FirstName,
			LastName:    testUser.LastName,
			DateOfBirth: testUser.DateOfBirth.UTC(),
		}
		mockedError := errors.New("test-error")
		mocks.MockUserRepo.EXPECT().UpdateProfileDetails(
			gomock.Any(),
			gomock.Eq(createdProfileUser),
		).Return(nil, mockedError)
		mocks.MockLogger.EXPECT().Error(
			mockedError,
			"Error getting user by ID",
		)

		// Test RefreshToken
		updateResponse, resultError := mocks.UserService.UpdateProfileDetails(
			mocks.Ctx,
			testUser.ID.Hex(),
			profileDetails,
		)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, updateResponse)
		assert.EqualError(test, resultError, "Error getting user by ID")
	})

	test.Run("UpdateUserProfile_ValidateFirstName_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()
		testUser := model.NewUser()
		profileDetails := &pb_authentication.UpdateUserProfileRequest{
			FirstName:   "",
			LastName:    testUser.LastName,
			DateOfBirth: timestamppb.New(testUser.DateOfBirth),
		}

		// Test RefreshToken
		updateResponse, resultError := mocks.UserService.UpdateProfileDetails(
			mocks.Ctx,
			testUser.ID.Hex(),
			profileDetails,
		)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, updateResponse)
		assert.EqualError(test, resultError, "Key: 'User.FirstName' Error:Field validation for 'FirstName' failed on the 'required' tag")
	})

	test.Run("UpdateUserProfile_ValidateLastName_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()
		testUser := model.NewUser()
		profileDetails := &pb_authentication.UpdateUserProfileRequest{
			FirstName:   testUser.FirstName,
			LastName:    "user.LastNameuser.LastNameuser.LastNameuser.LastNameuser.LastNameuser.LastNameuser.LastNameuser.LastNameuser.LastName",
			DateOfBirth: timestamppb.New(testUser.DateOfBirth),
		}

		// Test RefreshToken
		updateResponse, resultError := mocks.UserService.UpdateProfileDetails(
			mocks.Ctx,
			testUser.ID.Hex(),
			profileDetails,
		)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, updateResponse)
		assert.EqualError(test, resultError, "Key: 'User.LastName' Error:Field validation for 'LastName' failed on the 'max' tag")
	})

	test.Run("UpdateUserProfile_ValidateDOB_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()
		testUser := model.NewUser()
		profileDetails := &pb_authentication.UpdateUserProfileRequest{
			FirstName:   testUser.FirstName,
			LastName:    testUser.LastName,
			DateOfBirth: timestamppb.New(testUser.DateOfBirth.Add(1 * time.Hour)),
		}

		// Test RefreshToken
		updateResponse, resultError := mocks.UserService.UpdateProfileDetails(
			mocks.Ctx,
			testUser.ID.Hex(),
			profileDetails,
		)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, updateResponse)
		assert.EqualError(test, resultError, "Key: 'User.DateOfBirth' Error:Field validation for 'DateOfBirth' failed on the 'not_future' tag")
	})

	test.Run("DeleteAccount_Success", func(test *testing.T) {
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		// Arrange
		validUserID := primitive.NewObjectID()
		user := &model.User{
			ID:        validUserID,
			Email:     "test@email.com",
			FirstName: "name",
			LastName:  "surname",
		}
		mocks.MockUserRepo.EXPECT().GetByUserID(
			gomock.Any(),
			validUserID,
		).Return(user, nil)
		mocks.MockUserRepo.EXPECT().DeleteByUserID(
			gomock.Any(),
			validUserID,
		).Return(nil)
		mocks.MockEmailService.EXPECT().SendDeletedUserEmail(
			gomock.Any(),
			user.Email,
			user.FirstName,
		)

		// Act
		err := mocks.UserService.DeleteUser(mocks.Ctx, validUserID.Hex())

		// Assert
		assert.NoError(test, err)
	})

	test.Run("DeleteAccount_InvalidUserID_Error", func(test *testing.T) {
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		// The logger expects an error about converting userID to ObjectID
		invalidUserID := "invalid-hex-id"
		mocks.MockLogger.EXPECT().Error(
			gomock.Any(), // We'll match any error object
			fmt.Sprintf("Could not convert user ID %s to ObjectID", invalidUserID),
		)

		// Act
		err := mocks.UserService.DeleteUser(mocks.Ctx, invalidUserID)

		// Assert
		assert.Error(test, err)
		assert.EqualError(test, err, "Invalid user ID")
	})

	test.Run("DeleteAccount_FindUserError", func(test *testing.T) {
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		// Arrange
		validUserID := primitive.NewObjectID()
		mocks.MockUserRepo.EXPECT().GetByUserID(
			gomock.Any(),
			validUserID,
		).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(
			errExample,
			fmt.Sprintf("User ID %s does not exist", validUserID.Hex()),
		)

		// Act
		err := mocks.UserService.DeleteUser(mocks.Ctx, validUserID.Hex())

		// Assert
		assert.Error(test, err)
		assert.EqualError(test, err, "Error deleting user by ID")
	})

	test.Run("DeleteAccount_RepositoryError", func(test *testing.T) {
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		// Arrange
		validUserID := primitive.NewObjectID()
		user := &model.User{
			ID:        validUserID,
			Email:     "test@email.com",
			FirstName: "name",
			LastName:  "surname",
		}
		mocks.MockUserRepo.EXPECT().GetByUserID(
			gomock.Any(),
			validUserID,
		).Return(user, nil)
		mocks.MockUserRepo.EXPECT().DeleteByUserID(
			gomock.Any(),
			validUserID,
		).Return(errExample)
		mocks.MockLogger.EXPECT().Error(
			errExample,
			"Error deleting user by ID",
		)

		// Act
		err := mocks.UserService.DeleteUser(mocks.Ctx, validUserID.Hex())

		// Assert
		assert.Error(test, err)
		assert.EqualError(test, err, "Error deleting user by ID")
	})

	// GetUserByID
	test.Run("GetUserByID_Success", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		testUser.ID = userID
		testUser.Email = testEmail

		mocks.MockUserRepo.EXPECT().GetByUserID(
			gomock.Any(),
			userID,
		).Return(testUser, nil)

		// Act
		user, err := mocks.UserService.GetUserByID(mocks.Ctx, userID.Hex())

		// Assert
		assert.NoError(test, err)
		assert.NotNil(test, user)
		assert.Equal(test, testUser.Email, user.Email)
		assert.Equal(test, testUser.ID, user.ID)
	})

	test.Run("GetUserByID_InvalidID_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		invalidID := "invalid-id"
		mocks.MockLogger.EXPECT().Error(
			gomock.Any(),
			fmt.Sprintf("Could not convert user ID %s to ObjectID", invalidID),
		)

		// Act
		user, err := mocks.UserService.GetUserByID(mocks.Ctx, invalidID)

		// Assert
		assert.Error(test, err)
		assert.Nil(test, user)
		assert.Equal(test, InvalidUserIDError, err.Error())
	})

	test.Run("GetUserByID_Repository_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().GetByUserID(
			gomock.Any(),
			userID,
		).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error getting user by ID")

		// Act
		user, err := mocks.UserService.GetUserByID(mocks.Ctx, userID.Hex())

		// Assert
		assert.Error(test, err)
		assert.Nil(test, user)
		assert.Equal(test, "Error getting user by ID", err.Error())
	})
}

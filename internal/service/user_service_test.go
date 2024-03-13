package service

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang/mock/gomock"
	"github.com/quadev-ltd/qd-common/pkg/log"
	loggerMock "github.com/quadev-ltd/qd-common/pkg/log/mock"
	commonToken "github.com/quadev-ltd/qd-common/pkg/token"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"google.golang.org/protobuf/types/known/timestamppb"

	jwtPkg "qd-authentication-api/internal/jwt"
	"qd-authentication-api/internal/model"
	repositoryMock "qd-authentication-api/internal/repository/mock"
	serviceMock "qd-authentication-api/internal/service/mock"
	"qd-authentication-api/pb/gen/go/pb_authentication"
)

const (
	testEmail     = "test@example.com"
	testPassword  = "Password123!"
	testFirstName = "John"
	testLastName  = "Doe"
	invalidEmail  = "invalid-email"
)

var (
	testDateOfBirth         = time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	userID                  = primitive.NewObjectID()
	errExample              = errors.New("test-error")
	refreshTokenValue       = "refresh-token"
	resetPasswordTokenValue = "reset-password-token"
	verificationTokenValue  = "MjAyNDAzMDlfClvE5pSXfIepywonOEgHvOEbWFj0_wSrg4feaV9SYw=="
	verificationTokenHash   = "$2a$10$lIVkFYORGPHIr5DgPwM3yO2uOkumFJ.RWF3IDHqp0xnqqlGjQ1cb6"
	testTokenValue          = "test-token-hash"
	testTokenHashValue      = "test-token-hash"
	newRefreshTokenValue    = "test_token_example"
	accessTokenClaims       = &jwtPkg.TokenClaims{
		Email:  testEmail,
		Type:   commonToken.AccessTokenType,
		Expiry: time.Now().Add(5 * time.Minute),
	}
	refreshTokenClaims = &jwtPkg.TokenClaims{
		Email:  testEmail,
		Type:   commonToken.RefreshTokenType,
		Expiry: time.Now().Add(5 * time.Minute),
	}
)

type AuthServiceMockedParams struct {
	MockUserRepo     repositoryMock.MockUserRepositoryer
	MockEmailService serviceMock.MockEmailServicer
	MockLogger       *loggerMock.MockLoggerer
	UserService      UserServicer
	Controller       *gomock.Controller
	Ctx              context.Context
}

// TODO: return an object
func createUserService(test *testing.T) *AuthServiceMockedParams {
	controller := gomock.NewController(test)
	mockUserRepo := repositoryMock.NewMockUserRepositoryer(controller)
	mockEmailService := serviceMock.NewMockEmailServicer(controller)
	mockLogger := loggerMock.NewMockLoggerer(controller)
	userService := NewUserService(
		mockEmailService,
		mockUserRepo,
	)
	ctx := context.WithValue(context.Background(), log.LoggerKey, mockLogger)

	return &AuthServiceMockedParams{
		*mockUserRepo,
		*mockEmailService,
		mockLogger,
		userService,
		controller,
		ctx,
	}
}

func TestAuthenticationService(test *testing.T) {
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
		invalidDateOfBirth := time.Time{}

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

		// Test successful verification
		err := mocks.UserService.VerifyEmail(mocks.Ctx, testToken)

		assert.NoError(test, err)
		assert.Equal(test, model.AccountStatusVerified, testUser.AccountStatus)
	})

	test.Run("VerifyEmail_Get_User_By_ID_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testToken := model.NewToken(testTokenHashValue)

		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error getting user by ID")

		// Test Verify
		resultError := mocks.UserService.VerifyEmail(mocks.Ctx, testToken)

		assert.Error(test, resultError)
		assert.NotNil(test, resultError)
		assert.Equal(test, "Invalid verification token", resultError.Error())
	})
	test.Run("Invalid verification token", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testToken := model.NewToken(testTokenHashValue)
		testUser := model.NewUser()
		testUser.AccountStatus = model.AccountStatusVerified

		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)

		// Test Verify
		resultError := mocks.UserService.VerifyEmail(mocks.Ctx, testToken)

		assert.Error(test, resultError)
		assert.IsType(test, &Error{}, resultError)
		assert.Equal(test, "Email already verified", resultError.Error())
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
		resultError := mocks.UserService.VerifyEmail(mocks.Ctx, testToken)

		// Assert
		assert.Error(test, resultError)
		assert.Equal(test, "Error updating user status", resultError.Error())
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
	test.Run("Authenticate_Invalid_Password", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		email := "test@example.com"

		user := model.NewUser()
		invalidPassword := "invalidpassword"

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), email).Return(user, nil)

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

		user := model.NewUser()
		user.PasswordHash = "$2a$10$b4R.rxNHsELRW/JaqI1kS.CXO.xVamz.rwFXxchWD2pdKhKzZp94u"
		user.PasswordSalt = "7jQQnlalvK1E0iDzugF18ewa1Auf7R71Dr6OWnJbZbI="

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(user, nil)

		// Act
		resultUser, resultError := mocks.UserService.Authenticate(mocks.Ctx, testEmail, testPassword)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, resultUser)
		assert.Equal(test, user.PasswordHash, resultUser.PasswordHash)
		assert.Equal(test, user.PasswordSalt, resultUser.PasswordSalt)
		assert.Equal(test, user.FirstName, resultUser.FirstName)
		assert.Equal(test, user.LastName, resultUser.LastName)
		assert.Equal(test, user.Email, resultUser.Email)
	})

	// // ResendEmailVerification
	test.Run("ResendEmailVerification_GetByEmail_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		errExample := errors.New("User repository error")

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, fmt.Sprintf("Error getting user by email: %v", testEmail))

		// Act
		err := mocks.UserService.ResendEmailVerification(mocks.Ctx, testEmail, testTokenValue)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error searching user by email", err.Error())
	})

	test.Run("ResendEmailVerification_GetByEmail_NotFound", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, nil)

		// Act
		err := mocks.UserService.ResendEmailVerification(mocks.Ctx, testEmail, testTokenValue)

		// Assert
		assert.Error(test, err)
		assert.IsType(test, &Error{}, err)
		assert.Contains(test, err.Error(), "Invalid email")
	})

	test.Run("ResendEmailVerification_GetByEmail_AlreadyVerified", func(test *testing.T) {
		// Arrange

		user := model.NewUser()
		user.AccountStatus = model.AccountStatusVerified
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(user, nil)

		// Act
		err := mocks.UserService.ResendEmailVerification(mocks.Ctx, testEmail, testTokenValue)

		// Assert
		assert.Error(test, err)
		assert.IsType(test, &Error{}, err)
		assert.Contains(test, err.Error(), "Email already verified")
	})

	test.Run("ResendEmailVerification_SendEmail_Error", func(test *testing.T) {
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		errExample := errors.New("Email service error")

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)
		mocks.MockEmailService.EXPECT().SendVerificationMail(
			mocks.Ctx,
			testEmail,
			testUser.FirstName,
			testUser.ID.Hex(),
			gomock.Any(),
		).Return(errExample)

		// Act
		err := mocks.UserService.ResendEmailVerification(mocks.Ctx, testEmail, testTokenValue)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error sending verification email: Email service error", err.Error())
	})

	test.Run("ResendEmailVerification_Success", func(test *testing.T) {
		mocks := createUserService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)
		mocks.MockEmailService.EXPECT().SendVerificationMail(
			mocks.Ctx,
			testEmail,
			testUser.FirstName,
			testUser.ID.Hex(),
			testTokenHashValue,
		).Return(nil)

		// Act
		err := mocks.UserService.ResendEmailVerification(mocks.Ctx, testEmail, testTokenValue)

		// Assert
		assert.NoError(test, err)
	})

	// GetUserProfile
	test.Run("GetUserProfile_Success", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()
		user := model.NewUser()

		mocks.MockUserRepo.EXPECT().GetByUserID(
			gomock.Any(),
			user.ID,
		).Return(user, nil)

		// Test RefreshToken
		profileResult, resultError := mocks.UserService.GetUserProfile(
			mocks.Ctx,
			user.ID.Hex(),
		)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, profileResult)
		assert.True(test, reflect.DeepEqual(profileResult, user))
	})

	test.Run("GetUserProfile_GetUser_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()
		user := model.NewUser()
		mockedError := errors.New("test-error")

		mocks.MockUserRepo.EXPECT().GetByUserID(
			gomock.Any(),
			user.ID,
		).Return(nil, mockedError)
		mocks.MockLogger.EXPECT().Error(mockedError, "Error getting user by ID")

		// Test RefreshToken
		profileResult, resultError := mocks.UserService.GetUserProfile(
			mocks.Ctx,
			user.ID.Hex(),
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
		user := model.NewUser()
		profileDetails := &pb_authentication.UpdateUserProfileRequest{
			FirstName:   user.FirstName,
			LastName:    user.LastName,
			DateOfBirth: timestamppb.New(user.DateOfBirth),
		}
		createdProfileUser := &model.User{
			ID:          user.ID,
			FirstName:   user.FirstName,
			LastName:    user.LastName,
			DateOfBirth: user.DateOfBirth.UTC(),
		}

		mocks.MockUserRepo.EXPECT().UpdateProfileDetails(
			gomock.Any(),
			gomock.Eq(createdProfileUser),
		).Return(user, nil)

		// Test RefreshToken
		updateResponse, resultError := mocks.UserService.UpdateProfileDetails(
			mocks.Ctx,
			user.ID.Hex(),
			profileDetails,
		)

		// Assert
		assert.NoError(test, resultError)
		assert.Equal(test, user.ID.Hex(), updateResponse.ID.Hex())
		assert.Equal(test, user.FirstName, updateResponse.FirstName)
		assert.Equal(test, user.LastName, updateResponse.LastName)
		assert.Equal(test, user.DateOfBirth.Unix(), updateResponse.DateOfBirth.Unix())
		assert.Equal(test, user.Email, updateResponse.Email)
		assert.Equal(test, user.AccountStatus, updateResponse.AccountStatus)
	})

	test.Run("UpdateUserProfile_Update_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()
		user := model.NewUser()
		profileDetails := &pb_authentication.UpdateUserProfileRequest{
			FirstName:   user.FirstName,
			LastName:    user.LastName,
			DateOfBirth: timestamppb.New(user.DateOfBirth),
		}
		createdProfileUser := &model.User{
			ID:          user.ID,
			FirstName:   user.FirstName,
			LastName:    user.LastName,
			DateOfBirth: user.DateOfBirth.UTC(),
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
			user.ID.Hex(),
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
		user := model.NewUser()
		profileDetails := &pb_authentication.UpdateUserProfileRequest{
			FirstName:   "J",
			LastName:    user.LastName,
			DateOfBirth: timestamppb.New(user.DateOfBirth),
		}

		// Test RefreshToken
		updateResponse, resultError := mocks.UserService.UpdateProfileDetails(
			mocks.Ctx,
			user.ID.Hex(),
			profileDetails,
		)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, updateResponse)
		assert.EqualError(test, resultError, "Key: 'User.FirstName' Error:Field validation for 'FirstName' failed on the 'min' tag")
	})

	test.Run("UpdateUserProfile_ValidateLastName_Error", func(test *testing.T) {
		// Arrange
		mocks := createUserService(test)
		defer mocks.Controller.Finish()
		user := model.NewUser()
		profileDetails := &pb_authentication.UpdateUserProfileRequest{
			FirstName:   user.FirstName,
			LastName:    "user.LastNameuser.LastNameuser.LastNameuser.LastNameuser.LastNameuser.LastNameuser.LastNameuser.LastNameuser.LastName",
			DateOfBirth: timestamppb.New(user.DateOfBirth),
		}

		// Test RefreshToken
		updateResponse, resultError := mocks.UserService.UpdateProfileDetails(
			mocks.Ctx,
			user.ID.Hex(),
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
		user := model.NewUser()
		profileDetails := &pb_authentication.UpdateUserProfileRequest{
			FirstName:   user.FirstName,
			LastName:    user.LastName,
			DateOfBirth: timestamppb.New(user.DateOfBirth.Add(1 * time.Hour)),
		}

		// Test RefreshToken
		updateResponse, resultError := mocks.UserService.UpdateProfileDetails(
			mocks.Ctx,
			user.ID.Hex(),
			profileDetails,
		)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, updateResponse)
		assert.EqualError(test, resultError, "Key: 'User.DateOfBirth' Error:Field validation for 'DateOfBirth' failed on the 'not_future' tag")
	})
}

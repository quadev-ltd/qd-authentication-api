package service

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/quadev-ltd/qd-common/pkg/log"
	loggerMock "github.com/quadev-ltd/qd-common/pkg/log/mock"
	commonToken "github.com/quadev-ltd/qd-common/pkg/token"
	"github.com/stretchr/testify/assert"

	"qd-authentication-api/internal/model"
	repositoryMock "qd-authentication-api/internal/repository/mock"
	serviceMock "qd-authentication-api/internal/service/mock"
)

type PasswordServiceMockedParams struct {
	MockUserRepo     repositoryMock.MockUserRepositoryer
	MockEmailService serviceMock.MockEmailServicer
	MockTokenService serviceMock.MockTokenServicer
	MockLogger       *loggerMock.MockLoggerer
	PasswordService  PasswordServicer
	Controller       *gomock.Controller
	Ctx              context.Context
}

type userAuthTypeMatcher struct {
	expectedUser *model.User
}

func (m *userAuthTypeMatcher) Matches(x interface{}) bool {
	user, ok := x.(*model.User)
	if !ok {
		return false
	}

	if len(user.AuthTypes) != len(m.expectedUser.AuthTypes) {
		return false
	}
	for i, authType := range user.AuthTypes {
		if authType != m.expectedUser.AuthTypes[i] {
			return false
		}
	}
	return true
}

func (m *userAuthTypeMatcher) String() string {
	return fmt.Sprintf("AuthType array is equal to AuthType array in %v", m.expectedUser)
}

func createPasswordService(test *testing.T) *PasswordServiceMockedParams {
	controller := gomock.NewController(test)
	mockUserRepo := repositoryMock.NewMockUserRepositoryer(controller)
	mockEmailService := serviceMock.NewMockEmailServicer(controller)
	mockTokenService := serviceMock.NewMockTokenServicer(controller)
	mockLogger := loggerMock.NewMockLoggerer(controller)
	passwordService := NewPasswordService(
		mockEmailService,
		mockTokenService,
		mockUserRepo,
	)
	ctx := context.WithValue(context.Background(), log.LoggerKey, mockLogger)

	return &PasswordServiceMockedParams{
		*mockUserRepo,
		*mockEmailService,
		*mockTokenService,
		mockLogger,
		passwordService,
		controller,
		ctx,
	}
}

func TestPasswordService(test *testing.T) {
	// ForgotPassword
	test.Run("ForgotPassword_Success", func(test *testing.T) {

		mocks := createPasswordService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		testUser.AccountStatus = model.AccountStatusVerified

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)
		mocks.MockTokenService.EXPECT().GeneratePasswordResetToken(gomock.Any(), testUser.ID).Return(&testTokenHashValue, nil)
		mocks.MockEmailService.EXPECT().SendPasswordResetEmail(
			mocks.Ctx,
			testEmail,
			testUser.FirstName,
			testUser.ID.Hex(),
			gomock.Any(),
		).Return(nil)

		// Act
		err := mocks.PasswordService.ForgotPassword(mocks.Ctx, testEmail)

		// Assert
		assert.NoError(test, err)
	})

	test.Run("ForgotPassword_SendEmail_Error", func(test *testing.T) {

		mocks := createPasswordService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		testUser.AccountStatus = model.AccountStatusVerified

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)
		mocks.MockTokenService.EXPECT().GeneratePasswordResetToken(gomock.Any(), testUser.ID).Return(&testTokenHashValue, nil)
		mocks.MockEmailService.EXPECT().SendPasswordResetEmail(
			mocks.Ctx,
			testEmail,
			testUser.FirstName,
			testUser.ID.Hex(),
			gomock.Any(),
		).Return(errExample)

		// Act
		err := mocks.PasswordService.ForgotPassword(mocks.Ctx, testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error sending password reset email for test@example.com: test-error", err.Error())
	})

	test.Run("ForgotPassword_GenerateToken_Error", func(test *testing.T) {
		mocks := createPasswordService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		testUser.AccountStatus = model.AccountStatusVerified

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)
		mocks.MockTokenService.EXPECT().GeneratePasswordResetToken(gomock.Any(), testUser.ID).Return(nil, errExample)

		// Act
		err := mocks.PasswordService.ForgotPassword(mocks.Ctx, testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Could not generate reset password token for user 000000000000000000000000: test-error", err.Error())
	})

	test.Run("ForgotPassword_GetByEmail_Error", func(test *testing.T) {

		mocks := createPasswordService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error retrieving user by email: test@example.com")
		// Act
		err := mocks.PasswordService.ForgotPassword(mocks.Ctx, testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error trying to get user from DB", err.Error())
	})

	test.Run("ForgotPassword_NotFound_Error", func(test *testing.T) {

		mocks := createPasswordService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, nil)
		mocks.MockLogger.EXPECT().Error(nil, "User email does not exist in DB: test@example.com")
		// Act
		err := mocks.PasswordService.ForgotPassword(mocks.Ctx, testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error getting user by email", err.Error())
	})

	// ResetPassword
	test.Run("ResetPassword_Success", func(test *testing.T) {
		// Arrange
		mocks := createPasswordService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()

		testToken := model.NewToken(testTokenHashValue)
		testToken.Type = commonToken.ResetPasswordTokenType
		testToken.UserID = testUser.ID
		testPassword := "NewPassword@123"

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(
			gomock.Any(),
			testToken.UserID.Hex(),
			resetPasswordTokenValue,
		).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)
		mocks.MockUserRepo.EXPECT().UpdatePassword(gomock.Any(), testUser).Return(nil)
		mocks.MockEmailService.EXPECT().SendPasswordResetSuccessEmail(
			gomock.Any(),
			testUser.Email,
			testUser.FirstName,
		).Return(nil)
		mocks.MockTokenService.EXPECT().RemoveUsedToken(gomock.Any(), testToken).Return(nil)

		err := mocks.PasswordService.ResetPassword(
			mocks.Ctx,
			testUser.ID.Hex(),
			resetPasswordTokenValue,
			testPassword,
		)
		assert.NoError(test, err)
	})

	test.Run("ResetPassword_Success_AuthTypeAdded", func(test *testing.T) {
		// Arrange
		mocks := createPasswordService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()
		testUser.AuthTypes = []model.AuthenticationType{}
		resultUser := model.NewUser()

		testToken := model.NewToken(testTokenHashValue)
		testToken.Type = commonToken.ResetPasswordTokenType
		testToken.UserID = testUser.ID
		testPassword := "NewPassword@123"

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(
			gomock.Any(),
			testToken.UserID.Hex(),
			resetPasswordTokenValue,
		).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)
		mocks.MockUserRepo.EXPECT().UpdatePassword(
			gomock.Any(),
			&userAuthTypeMatcher{expectedUser: resultUser},
		).Return(nil)
		mocks.MockEmailService.EXPECT().SendPasswordResetSuccessEmail(
			gomock.Any(),
			testUser.Email,
			testUser.FirstName,
		).Return(nil)
		mocks.MockTokenService.EXPECT().RemoveUsedToken(gomock.Any(), testToken).Return(nil)

		err := mocks.PasswordService.ResetPassword(
			mocks.Ctx,
			testUser.ID.Hex(),
			resetPasswordTokenValue,
			testPassword,
		)
		assert.NoError(test, err)
	})

	test.Run("ResetPassword_RemoveToken_Error_Succeeds", func(test *testing.T) {
		// Arrange
		mocks := createPasswordService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()

		testToken := model.NewToken(testTokenHashValue)
		testToken.Type = commonToken.ResetPasswordTokenType
		testToken.UserID = testUser.ID
		testPassword := "NewPassword@123"

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(
			gomock.Any(),
			testToken.UserID.Hex(),
			resetPasswordTokenValue,
		).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)
		mocks.MockUserRepo.EXPECT().UpdatePassword(gomock.Any(), testUser).Return(nil)
		mocks.MockEmailService.EXPECT().SendPasswordResetSuccessEmail(
			gomock.Any(),
			testUser.Email,
			testUser.FirstName,
		).Return(nil)
		mocks.MockTokenService.EXPECT().RemoveUsedToken(gomock.Any(), testToken).Return(errExample)
		mocks.MockLogger.EXPECT().Error(errExample, fmt.Sprintf("Error trying to remove used token for user ID %s", testToken.UserID.Hex()))

		err := mocks.PasswordService.ResetPassword(
			mocks.Ctx,
			testUser.ID.Hex(),
			resetPasswordTokenValue,
			testPassword,
		)
		assert.NoError(test, err)
	})

	test.Run("ResetPassword_SendError_Succeeeds", func(test *testing.T) {
		// Arrange
		mocks := createPasswordService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()

		testToken := model.NewToken(testTokenHashValue)
		testToken.Type = commonToken.ResetPasswordTokenType
		testToken.UserID = testUser.ID
		testPassword := "NewPassword@123"
		exampleError := errors.New("test-error")

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(
			gomock.Any(),
			testToken.UserID.Hex(),
			resetPasswordTokenValue,
		).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)
		mocks.MockUserRepo.EXPECT().UpdatePassword(gomock.Any(), testUser).Return(nil)
		mocks.MockEmailService.EXPECT().SendPasswordResetSuccessEmail(
			gomock.Any(),
			testUser.Email,
			testUser.FirstName,
		).Return(exampleError)
		mocks.MockTokenService.EXPECT().RemoveUsedToken(gomock.Any(), testToken).Return(nil)
		mocks.MockLogger.EXPECT().Error(exampleError, "Error trying to send a password reset notification for test@example.com")

		err := mocks.PasswordService.ResetPassword(
			mocks.Ctx,
			testUser.ID.Hex(),
			resetPasswordTokenValue,
			testPassword,
		)
		assert.NoError(test, err)
	})

	test.Run("ResetPassword_Update_Error", func(test *testing.T) {
		// Arrange
		mocks := createPasswordService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()

		testToken := model.NewToken(testTokenHashValue)
		testToken.Type = commonToken.ResetPasswordTokenType
		testToken.UserID = testUser.ID
		testPassword := "NewPassword@123"

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(
			gomock.Any(),
			testToken.UserID.Hex(),
			resetPasswordTokenValue,
		).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)
		mocks.MockUserRepo.EXPECT().UpdatePassword(gomock.Any(), testUser).Return(errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error updating user")

		err := mocks.PasswordService.ResetPassword(
			mocks.Ctx,
			testUser.ID.Hex(),
			resetPasswordTokenValue,
			testPassword,
		)

		assert.Error(test, err)
		assert.Equal(test, "Error updating user", err.Error())
	})

	test.Run("ResetPassword_SimplePassword_Error", func(test *testing.T) {
		// Arrange
		mocks := createPasswordService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()

		testToken := model.NewToken(testTokenHashValue)
		testToken.Type = commonToken.ResetPasswordTokenType
		testToken.UserID = testUser.ID
		testPassword := "simplePasswwrod123"

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(
			gomock.Any(),
			testUser.ID.Hex(),
			resetPasswordTokenValue,
		).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)

		err := mocks.PasswordService.ResetPassword(
			mocks.Ctx,
			testUser.ID.Hex(),
			resetPasswordTokenValue,
			testPassword,
		)

		assert.Error(test, err)
		assert.Equal(test, "Password does not meet complexity requirements", err.Error())
	})

	test.Run("ResetPassword_GetByUserID_Error", func(test *testing.T) {
		// Arrange
		mocks := createPasswordService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()

		testToken := model.NewToken(testTokenHashValue)
		testToken.Type = commonToken.ResetPasswordTokenType
		testToken.UserID = testUser.ID
		testPassword := "NewPassword@123"

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(
			gomock.Any(),
			testUser.ID.Hex(),
			resetPasswordTokenValue,
		).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error getting user assigned to the token")

		err := mocks.PasswordService.ResetPassword(
			mocks.Ctx,
			testUser.ID.Hex(),
			resetPasswordTokenValue,
			testPassword,
		)

		assert.Error(test, err)
		assert.Equal(test, "Error getting user assigned to the token", err.Error())
	})

	test.Run("ResetPassword_Token_Error", func(test *testing.T) {
		// Arrange
		mocks := createPasswordService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()

		testToken := model.NewToken(testTokenHashValue)
		testToken.Type = commonToken.ResetPasswordTokenType
		testToken.UserID = testUser.ID
		testPassword := "NewPassword@123"

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(
			gomock.Any(),
			testUser.ID.Hex(),
			resetPasswordTokenValue,
		).Return(nil, errExample)

		err := mocks.PasswordService.ResetPassword(
			mocks.Ctx,
			testUser.ID.Hex(),
			resetPasswordTokenValue,
			testPassword,
		)

		assert.Error(test, err)
		assert.Equal(test, "test-error", err.Error())
	})
}

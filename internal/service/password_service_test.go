package service

import (
	"context"
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
		mocks.MockEmailService.EXPECT().SendPasswordResetMail(
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
		mocks.MockEmailService.EXPECT().SendPasswordResetMail(
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
		assert.Equal(test, "Error sending password reset email: test-error", err.Error())
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
		assert.Equal(test, "Could not generate reset password token: test-error", err.Error())
	})

	test.Run("ForgotPassword_Unverified_Error", func(test *testing.T) {

		mocks := createPasswordService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)

		// Act
		err := mocks.PasswordService.ForgotPassword(mocks.Ctx, testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, fmt.Sprintf("Email account %s not verified yet", testUser.Email), err.Error())
	})

	test.Run("ForgotPassword_GetByEmail_Error", func(test *testing.T) {

		mocks := createPasswordService(test)
		defer mocks.Controller.Finish()

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error getting user by email")
		// Act
		err := mocks.PasswordService.ForgotPassword(mocks.Ctx, testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error getting user by email", err.Error())
	})

	// 	// ResetPassword
	test.Run("ResetPassword_Success", func(test *testing.T) {
		// Arrange
		mocks := createPasswordService(test)
		defer mocks.Controller.Finish()

		testUser := model.NewUser()

		testToken := model.NewToken(testTokenHashValue, testTokenSalt)
		testToken.Type = commonToken.ResetPasswordTokenType
		testToken.UserID = testUser.ID
		testPassword := "NewPassword@123"

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(
			gomock.Any(),
			resetPasswordTokenValue,
		).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)
		mocks.MockUserRepo.EXPECT().UpdatePassword(gomock.Any(), testUser).Return(nil)

		err := mocks.PasswordService.ResetPassword(
			mocks.Ctx,
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

		testToken := model.NewToken(testTokenHashValue, testTokenSalt)
		testToken.Type = commonToken.ResetPasswordTokenType
		testToken.UserID = testUser.ID
		testPassword := "NewPassword@123"

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(
			gomock.Any(),
			resetPasswordTokenValue,
		).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)
		mocks.MockUserRepo.EXPECT().UpdatePassword(gomock.Any(), testUser).Return(errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error updating user")

		err := mocks.PasswordService.ResetPassword(
			mocks.Ctx,
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

		testToken := model.NewToken(testTokenHashValue, testTokenSalt)
		testToken.Type = commonToken.ResetPasswordTokenType
		testToken.UserID = testUser.ID
		testPassword := "simplePasswwrod123"

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(gomock.Any(), resetPasswordTokenValue).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)

		err := mocks.PasswordService.ResetPassword(
			mocks.Ctx,
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

		testToken := model.NewToken(testTokenHashValue, testTokenSalt)
		testToken.Type = commonToken.ResetPasswordTokenType
		testToken.UserID = testUser.ID
		testPassword := "NewPassword@123"

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(gomock.Any(), resetPasswordTokenValue).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(nil, errExample)
		mocks.MockLogger.EXPECT().Error(errExample, "Error getting user assigned to the token")

		err := mocks.PasswordService.ResetPassword(
			mocks.Ctx,
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

		testToken := model.NewToken(testTokenHashValue, testTokenSalt)
		testToken.Type = commonToken.ResetPasswordTokenType
		testToken.UserID = testUser.ID
		testPassword := "NewPassword@123"

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(gomock.Any(), resetPasswordTokenValue).Return(nil, errExample)

		err := mocks.PasswordService.ResetPassword(
			mocks.Ctx,
			resetPasswordTokenValue,
			testPassword,
		)

		assert.Error(test, err)
		assert.Equal(test, "Unable to verify reset password token: test-error", err.Error())
	})
}

package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	commonJWT "github.com/quadev-ltd/qd-common/pkg/jwt"
	"github.com/quadev-ltd/qd-common/pkg/log"
	loggerMock "github.com/quadev-ltd/qd-common/pkg/log/mock"
	"github.com/stretchr/testify/assert"

	"qd-authentication-api/internal/model"
	repositoryMock "qd-authentication-api/internal/repository/mock"
	serviceMock "qd-authentication-api/internal/service/mock"
)

type PasswordServiceMockedParams struct {
	MockUserRepo     repositoryMock.MockUserRepositoryer
	MockEmailService serviceMock.MockEmailServicer
	MockTokenService serviceMock.MockTokenServicer
	PasswordService  PasswordServicer
}

func createPasswordService(controller *gomock.Controller) *PasswordServiceMockedParams {
	mockUserRepo := repositoryMock.NewMockUserRepositoryer(controller)
	mockEmailService := serviceMock.NewMockEmailServicer(controller)
	mockTokenService := serviceMock.NewMockTokenServicer(controller)
	passwordService := NewPasswordService(
		mockEmailService,
		mockTokenService,
		mockUserRepo,
	)

	return &PasswordServiceMockedParams{
		*mockUserRepo,
		*mockEmailService,
		*mockTokenService,
		passwordService,
	}
}

func TestPasswordService(test *testing.T) {
	// ForgotPassword
	test.Run("ForgotPassword_Success", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createPasswordService(controller)

		testUser := model.NewUser()
		testUser.AccountStatus = model.AccountStatusVerified

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)
		mocks.MockTokenService.EXPECT().GeneratePasswordResetToken(gomock.Any(), testUser.ID).Return(&testTokenValue, nil)
		mocks.MockEmailService.EXPECT().SendPasswordResetMail(
			context.Background(),
			testEmail,
			testUser.FirstName,
			gomock.Any(),
		).Return(nil)

		// Act
		err := mocks.PasswordService.ForgotPassword(context.Background(), testEmail)

		// Assert
		assert.NoError(test, err)
	})

	test.Run("ForgotPassword_SendEmail_Error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createPasswordService(controller)

		testUser := model.NewUser()
		testUser.AccountStatus = model.AccountStatusVerified

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)
		mocks.MockTokenService.EXPECT().GeneratePasswordResetToken(gomock.Any(), testUser.ID).Return(&testTokenValue, nil)
		mocks.MockEmailService.EXPECT().SendPasswordResetMail(
			context.Background(),
			testEmail,
			testUser.FirstName,
			gomock.Any(),
		).Return(errExample)

		// Act
		err := mocks.PasswordService.ForgotPassword(context.Background(), testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error sending password reset email: test-error", err.Error())
	})

	test.Run("ForgotPassword_GenerateToken_Error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createPasswordService(controller)

		testUser := model.NewUser()
		testUser.AccountStatus = model.AccountStatusVerified

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)
		mocks.MockTokenService.EXPECT().GeneratePasswordResetToken(gomock.Any(), testUser.ID).Return(nil, errExample)

		// Act
		err := mocks.PasswordService.ForgotPassword(context.Background(), testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "test-error", err.Error())
	})

	// 	test.Run("ForgotPassword_InsertToken_Error", func(test *testing.T) {
	// 		controller := gomock.NewController(test)
	// 		defer controller.Finish()

	// 		mockUserRepo,
	// 			mockTokenRepo,
	// 			_,
	// 			_,
	// 			PasswordService := createPasswordService(controller)

	// 		testUser := model.NewUser()
	// 		testUser.AccountStatus = model.AccountStatusVerified

	// 		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)
	// 		mockTokenRepo.EXPECT().InsertToken(gomock.Any(), gomock.Any()).Return(nil, errExample)

	// 		// Act
	// 		err := PasswordService.ForgotPassword(context.Background(), testEmail)

	// 		// Assert
	// 		assert.Error(test, err)
	// 		assert.Equal(test, "Error inserting token in db: test-error", err.Error())
	// 	})

	test.Run("ForgotPassword_Unverified_Error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createPasswordService(controller)

		testUser := model.NewUser()

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)

		// Act
		err := mocks.PasswordService.ForgotPassword(context.Background(), testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, fmt.Sprintf("Email account %s not verified yet", testUser.Email), err.Error())
	})

	test.Run("ForgotPassword_GetByEmail_Error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		mocks := createPasswordService(controller)

		mocks.MockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, errExample)

		// Act
		err := mocks.PasswordService.ForgotPassword(context.Background(), testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error getting user by email: test-error", err.Error())
	})

	// 	// ResetPassword
	test.Run("ResetPassword_Success", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()
		mocks := createPasswordService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		testUser := model.NewUser()
		testTokenValue := "test-token"
		testToken := model.NewToken(testTokenValue)
		testToken.Type = commonJWT.ResetPasswordTokenType
		testToken.UserID = testUser.ID
		testPassword := "NewPassword@123"

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(gomock.Any(), testToken.Token).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)
		mocks.MockUserRepo.EXPECT().UpdatePassword(gomock.Any(), testUser).Return(nil)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		err := mocks.PasswordService.ResetPassword(
			ctx,
			testToken.Token,
			testPassword,
		)
		assert.NoError(test, err)
	})

	test.Run("ResetPassword_Update_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()
		mocks := createPasswordService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		testUser := model.NewUser()
		testTokenValue := "test-token"
		testToken := model.NewToken(testTokenValue)
		testToken.Type = commonJWT.ResetPasswordTokenType
		testToken.UserID = testUser.ID
		testPassword := "NewPassword@123"

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(gomock.Any(), testToken.Token).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)
		mocks.MockUserRepo.EXPECT().UpdatePassword(gomock.Any(), testUser).Return(errExample)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		err := mocks.PasswordService.ResetPassword(
			ctx,
			testToken.Token,
			testPassword,
		)

		assert.Error(test, err)
		assert.Equal(test, "Error updating user: test-error", err.Error())
	})

	test.Run("ResetPassword_SimplePassword_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()
		mocks := createPasswordService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		testUser := model.NewUser()
		testTokenValue := "test-token"
		testToken := model.NewToken(testTokenValue)
		testToken.Type = commonJWT.ResetPasswordTokenType
		testToken.UserID = testUser.ID
		testPassword := "simplePasswwrod123"

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(gomock.Any(), testToken.Token).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		err := mocks.PasswordService.ResetPassword(
			ctx,
			testToken.Token,
			testPassword,
		)

		assert.Error(test, err)
		assert.Equal(test, "Password does not meet complexity requirements", err.Error())
	})

	test.Run("ResetPassword_GetByUserID_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()
		mocks := createPasswordService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		testUser := model.NewUser()
		testTokenValue := "test-token"
		testToken := model.NewToken(testTokenValue)
		testToken.Type = commonJWT.ResetPasswordTokenType
		testToken.UserID = testUser.ID
		testPassword := "NewPassword@123"

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(gomock.Any(), testToken.Token).Return(testToken, nil)
		mocks.MockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(nil, errExample)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		err := mocks.PasswordService.ResetPassword(
			ctx,
			testToken.Token,
			testPassword,
		)

		assert.Error(test, err)
		assert.Equal(test, "Error getting user assigned to the token: test-error", err.Error())
	})

	test.Run("ResetPassword_Token_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()
		mocks := createPasswordService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		testUser := model.NewUser()
		testTokenValue := "test-token"
		testToken := model.NewToken(testTokenValue)
		testToken.Type = commonJWT.ResetPasswordTokenType
		testToken.UserID = testUser.ID
		testPassword := "NewPassword@123"

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(gomock.Any(), testToken.Token).Return(nil, errExample)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		err := mocks.PasswordService.ResetPassword(
			ctx,
			testToken.Token,
			testPassword,
		)

		assert.Error(test, err)
		assert.Equal(test, "test-error", err.Error())
	})
}

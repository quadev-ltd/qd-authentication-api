package service

import (
	"context"
	"fmt"

	commonLogger "github.com/quadev-ltd/qd-common/pkg/log"

	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/repository"
	"qd-authentication-api/internal/util"
)

// PasswordServicer is the interface for the authentication service
type PasswordServicer interface {
	ForgotPassword(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, password string) error
}

// PasswordService is the implementation of the authentication service
type PasswordService struct {
	emailService   EmailServicer
	tokenService   TokenServicer
	userRepository repository.UserRepositoryer
}

var _ PasswordServicer = &PasswordService{}

// NewPasswordService creates a new authentication service
func NewPasswordService(
	emailService EmailServicer,
	tokenService TokenServicer,
	userRepository repository.UserRepositoryer,
) PasswordServicer {
	return &PasswordService{
		emailService,
		tokenService,
		userRepository,
	}
}

// ForgotPassword sends a password reset email
func (service *PasswordService) ForgotPassword(ctx context.Context, email string) error {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return err
	}
	user, err := service.userRepository.GetByEmail(ctx, email)
	if err != nil {
		logger.Error(err, "Error getting user by email")
		return &Error{Message: "Error getting user by email"}
	}
	if user.AccountStatus == model.AccountStatusUnverified {
		return &Error{Message: fmt.Sprintf("Email account %s not verified yet", email)}
	}
	resetToken, err := service.tokenService.GeneratePasswordResetToken(ctx, user.ID)
	if err != nil {
		return fmt.Errorf("Could not generate reset password token: %v", err)
	}
	if err := service.emailService.SendPasswordResetMail(
		ctx,
		user.Email,
		user.FirstName,
		user.ID.Hex(),
		*resetToken,
	); err != nil {
		return fmt.Errorf("Error sending password reset email: %v", err)
	}
	return nil
}

// ResetPassword resets the user password
func (service *PasswordService) ResetPassword(ctx context.Context, tokenValue, password string) error {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return err
	}
	token, err := service.tokenService.VerifyResetPasswordToken(ctx, tokenValue)
	if err != nil {
		return fmt.Errorf("Unable to verify reset password token: %v", err)
	}
	user, err := service.userRepository.GetByUserID(ctx, token.UserID)
	if err != nil {
		logger.Error(err, "Error getting user assigned to the token")
		return fmt.Errorf("Error getting user assigned to the token")
	}
	if !model.IsPasswordComplex(password) {
		return &NoComplexPasswordError{
			Message: "Password does not meet complexity requirements",
		}
	}
	hashedPassword, salt, err := util.GenerateHash(password, true)
	if err != nil {
		logger.Error(err, "Error generating password hash")
		return &Error{Message: "Error generating password hash"}
	}
	user.PasswordHash = string(hashedPassword)
	user.PasswordSalt = *salt
	if err := service.userRepository.UpdatePassword(ctx, user); err != nil {
		logger.Error(err, "Error updating user")
		return &Error{Message: "Error updating user"}
	}
	return nil
}

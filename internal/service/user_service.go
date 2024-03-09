package service

import (
	"context"
	"fmt"
	"time"

	"github.com/quadev-ltd/qd-common/pkg/log"
	commonToken "github.com/quadev-ltd/qd-common/pkg/token"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"

	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/repository"
	"qd-authentication-api/internal/util"
)

// UserServicer is the interface for the authentication service
type UserServicer interface {
	Register(ctx context.Context, email, password, firstName, lastName string, dateOfBirth *time.Time) error
	ResendEmailVerification(ctx context.Context, email string) error
	VerifyEmail(ctx context.Context, userID, verificationToken string) error
	Authenticate(ctx context.Context, email, password string) (*model.AuthTokensResponse, error)
	RefreshToken(ctx context.Context, refreshTokenString string) (*model.AuthTokensResponse, error)
}

// UserService is the implementation of the authentication service
type UserService struct {
	emailService   EmailServicer
	tokenService   TokenServicer
	userRepository repository.UserRepositoryer
}

var _ UserServicer = &UserService{}

// NewUserService creates a new authentication service
func NewUserService(
	emailService EmailServicer,
	tokenService TokenServicer,
	userRepository repository.UserRepositoryer,
) UserServicer {
	return &UserService{
		emailService,
		tokenService,
		userRepository,
	}
}

// TODO pass an object DTO instead of all the parameters and check input validation

// Register registers a new user
func (service *UserService) Register(ctx context.Context, email, password, firstName, lastName string, dateOfBirth *time.Time) error {
	logger, err := log.GetLoggerFromContext(ctx)
	if err != nil {
		return err
	}
	userExists, err := service.userRepository.ExistsByEmail(ctx, email)
	if err != nil {
		logger.Error(err, fmt.Sprintf("Error checking user existence by email: %v", email))
		return fmt.Errorf("Error checking user existence by email: %v", email)
	}
	if userExists {
		return &model.EmailInUseError{Email: email}
	}
	if !model.IsPasswordComplex(password) {
		return &NoComplexPasswordError{
			Message: "Password does not meet complexity requirements",
		}
	}
	hashedPassword, salt, err := util.GenerateHash(password, true)
	if err != nil {
		logger.Error(err, "Error generating password hash")
		return fmt.Errorf("Error generating password hash")
	}

	user := &model.User{
		Email:            email,
		PasswordHash:     string(hashedPassword),
		PasswordSalt:     *salt,
		FirstName:        firstName,
		LastName:         lastName,
		DateOfBirth:      *dateOfBirth,
		RegistrationDate: time.Now(),
		AccountStatus:    model.AccountStatusUnverified,
	}

	// Validate the user object
	if err := model.ValidateUser(user); err != nil {
		return err
	}

	// Create the user in the repository
	insertedID, err := service.userRepository.InsertUser(ctx, user)
	if err != nil {
		logger.Error(err, "Error inserting user in DB")
		return fmt.Errorf("Error storing user")
	}

	// Create the verification token
	userID, ok := insertedID.(primitive.ObjectID)
	if !ok {
		return fmt.Errorf("InsertedID is not of type primitive.ObjectID")
	}
	emailVerificationToken, err := service.tokenService.GenerateEmailVerificationToken(ctx, userID)
	if err != nil {
		return err
	}

	if err = service.emailService.SendVerificationMail(
		ctx,
		user.Email,
		user.FirstName,
		userID.Hex(),
		*emailVerificationToken,
	); err != nil {
		return &SendEmailError{Message: "Error sending verification email"}
	}

	return nil
}

// ResendEmailVerification resends a verification email
func (service *UserService) ResendEmailVerification(
	ctx context.Context,
	email string,
) error {
	logger, err := log.GetLoggerFromContext(ctx)
	if err != nil {
		return err
	}
	user, err := service.userRepository.GetByEmail(ctx, email)
	if err != nil {
		logger.Error(err, fmt.Sprintf("Error getting user by email: %v", email))
		return fmt.Errorf("Error searching user by email")
	}
	if user == nil {
		return &Error{Message: "Invalid email"}
	}
	if user.AccountStatus == model.AccountStatusVerified {
		return &Error{Message: "Email already verified"}
	}

	emailVerificationToken, err := service.tokenService.GenerateEmailVerificationToken(ctx, user.ID)
	if err != nil {
		return err
	}

	if err := service.emailService.SendVerificationMail(
		ctx,
		user.Email,
		user.FirstName,
		user.ID.Hex(),
		*emailVerificationToken,
	); err != nil {
		return fmt.Errorf("Error sending verification email: %v", err)
	}

	return nil
}

// VerifyEmail verifies a user's email
func (service *UserService) VerifyEmail(ctx context.Context, userID, verificationToken string) error {
	logger, err := log.GetLoggerFromContext(ctx)
	if err != nil {
		return err
	}
	token, err := service.tokenService.VerifyEmailVerificationToken(ctx, userID, verificationToken)
	if err != nil {
		return err
	}

	user, err := service.userRepository.GetByUserID(ctx, token.UserID)
	if err != nil {
		logger.Error(err, "Error getting user by ID")
		return &Error{Message: "Invalid verification token"}
	}
	if user.AccountStatus == model.AccountStatusVerified {
		return &Error{Message: "Email already verified"}
	}

	user.AccountStatus = model.AccountStatusVerified

	if err := service.userRepository.UpdateStatus(ctx, user); err != nil {
		logger.Error(err, "Error updating user status")
		return fmt.Errorf("Error updating user status")
	}

	err = service.tokenService.RemoveUsedToken(ctx, token)
	if err != nil {
		return err
	}
	return nil
}

// Authenticate authenticates a user and provides a token
func (service *UserService) Authenticate(ctx context.Context, email, password string) (*model.AuthTokensResponse, error) {
	logger, err := log.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	user, resultError := service.userRepository.GetByEmail(ctx, email)
	if resultError != nil {
		logger.Error(resultError, fmt.Sprintf("Error getting user by email: %v", email))
		return nil, &Error{
			Message: "Error getting user by email",
		}
	}

	if user == nil {
		return nil, &model.WrongEmailOrPassword{FieldName: "Email"}
	}

	resultError = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password+user.PasswordSalt))
	if resultError != nil {
		return nil, &model.WrongEmailOrPassword{FieldName: "Password"}
	}

	return service.tokenService.GenerateJWTTokens(ctx, user.Email, user.ID.Hex())
}

// RefreshToken refreshes an authentication token using a refresh token
func (service *UserService) RefreshToken(ctx context.Context, refreshTokenString string) (*model.AuthTokensResponse, error) {
	claims, err := service.tokenService.VerifyJWTToken(ctx, refreshTokenString)
	if err != nil {
		return nil, err
	}
	if claims.Type != commonToken.RefreshTokenType {
		return nil, &Error{Message: "Invalid token type"}
	}

	return service.tokenService.GenerateJWTTokens(ctx, claims.Email, claims.UserID)
}

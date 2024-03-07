package service

import (
	"context"
	"fmt"
	"time"

	"github.com/quadev-ltd/qd-common/pkg/log"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"

	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/repository"
	"qd-authentication-api/internal/util"
)

// UserServicer is the interface for the authentication service
type UserServicer interface {
	Register(ctx context.Context, email, password, firstName, lastName string, dateOfBirth *time.Time) error
	VerifyEmail(ctx context.Context, verificationToken string) error
	Authenticate(ctx context.Context, email, password string) (*model.AuthTokensResponse, error)
	ResendEmailVerification(ctx context.Context, email string) error
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
		return fmt.Errorf("Error checking user existence by email: %v", err)
	}
	if userExists {
		return &model.EmailInUseError{Email: email}
	}
	if !model.IsPasswordComplex(password) {
		return &NoComplexPasswordError{
			Message: "Password does not meet complexity requirements",
		}
	}

	hashedPassword, salt, err := util.GenerateHash(password)
	if err != nil {
		return fmt.Errorf("Error generating password hash: %v", err)
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
		return fmt.Errorf("Error creating user: %v", err)
	}

	// Create the verification token
	userID, ok := insertedID.(primitive.ObjectID)
	if !ok {
		return fmt.Errorf("InsertedID is not of type primitive.ObjectID: %v", err)
	}
	emailVerificationToken, err := service.tokenService.GenerateEmailVerificationToken(ctx, userID)
	if err != nil {
		return err
	}

	if err = service.emailService.SendVerificationMail(ctx, user.Email, user.FirstName, *emailVerificationToken); err != nil {
		logger.Error(err, "Error sending verification email")
		return &SendEmailError{Message: "Error sending verification email"}
	}

	return nil
}

// VerifyEmail verifies a user's email
func (service *UserService) VerifyEmail(ctx context.Context, verificationToken string) error {
	token, err := service.tokenService.VerifyEmailVerificationToken(ctx, verificationToken)
	if err != nil {
		return err
	}

	user, err := service.userRepository.GetByUserID(ctx, token.UserID)
	if err != nil {
		return fmt.Errorf("Error getting user by ID: %v", err)
	}
	if user.AccountStatus == model.AccountStatusVerified {
		return &Error{Message: "Email already verified"}
	}

	user.AccountStatus = model.AccountStatusVerified

	if err := service.userRepository.UpdateStatus(ctx, user); err != nil {
		return fmt.Errorf("Error updating user: %v", err)
	}

	err = service.tokenService.RemoveUsedToken(ctx, token.Token)
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
		logger.Error(resultError, "Error getting user by email")
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

	return service.tokenService.GenerateJWTTokens(ctx, user, nil)
}

// ResendEmailVerification resends a verification email
func (service *UserService) ResendEmailVerification(
	ctx context.Context,
	email string,
) error {
	user, err := service.userRepository.GetByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("Error getting user by email: %v", err)
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
		*emailVerificationToken,
	); err != nil {
		return fmt.Errorf("Error sending verification email: %v", err)
	}

	return nil
}

// RefreshToken refreshes an authentication token using a refresh token
func (service *UserService) RefreshToken(ctx context.Context, refreshTokenString string) (*model.AuthTokensResponse, error) {
	email, err := service.tokenService.VerifyJWTToken(ctx, refreshTokenString)
	if err != nil {
		return nil, err
	}
	logger, err := log.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Retrieve user details from the database
	user, err := service.userRepository.GetByEmail(ctx, *email)
	if err != nil {
		logger.Error(err, "Error getting user by email")
		return nil, &Error{
			Message: "Error getting user by email",
		}
	}

	return service.tokenService.GenerateJWTTokens(ctx, user, &refreshTokenString)
}

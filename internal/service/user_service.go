package service

import (
	"context"
	"fmt"
	"time"

	"github.com/quadev-ltd/qd-common/pb/gen/go/pb_authentication"
	"github.com/quadev-ltd/qd-common/pkg/log"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"

	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/repository"
	"qd-authentication-api/internal/util"
)

// UserServicer is the interface for the authentication service
type UserServicer interface {
	Register(ctx context.Context, email, password, firstName, lastName string, dateOfBirth *time.Time) (*model.User, error)
	SendEmailVerification(ctx context.Context, user *model.User, emailVerificationToken string) error
	ResendEmailVerification(ctx context.Context, email *model.User, emailVerificationToken string) error
	VerifyEmail(ctx context.Context, token *model.Token) (*string, error)
	Authenticate(ctx context.Context, email, password string) (*model.User, error)
	GetUserProfile(ctx context.Context, userID string) (*model.User, error)
	UpdateProfileDetails(ctx context.Context, userID string, profileDetails *pb_authentication.UpdateUserProfileRequest) (*model.User, error)
}

// UserService is the implementation of the authentication service
type UserService struct {
	emailService   EmailServicer
	userRepository repository.UserRepositoryer
}

var _ UserServicer = &UserService{}

// NewUserService creates a new authentication service
func NewUserService(
	emailService EmailServicer,
	userRepository repository.UserRepositoryer,
) UserServicer {
	return &UserService{
		emailService,
		userRepository,
	}
}

// TODO pass an object DTO instead of all the parameters and check input validation

// Register registers a new user
func (service *UserService) Register(
	ctx context.Context,
	email,
	password,
	firstName,
	lastName string,
	dateOfBirth *time.Time,
) (*model.User, error) {
	logger, err := log.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	userExists, err := service.userRepository.ExistsByEmail(ctx, email)
	if err != nil {
		logger.Error(err, fmt.Sprintf("Error checking user existence by email: %v", email))
		return nil, fmt.Errorf("Error checking user existence by email: %v", email)
	}
	if userExists {
		return nil, &model.EmailInUseError{Email: email}
	}
	if !model.IsPasswordComplex(password) {
		return nil, &NoComplexPasswordError{
			Message: "Password does not meet complexity requirements",
		}
	}
	hashedPassword, salt, err := util.GenerateHash(password, true)
	if err != nil {
		logger.Error(err, "Error generating password hash")
		return nil, fmt.Errorf("Error generating password hash")
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
		return nil, err
	}

	// Create the user in the repository
	insertedID, err := service.userRepository.InsertUser(ctx, user)
	if err != nil {
		logger.Error(err, "Error inserting user in DB")
		return nil, fmt.Errorf("Error storing user")
	}

	// Create the verification token
	userID, ok := insertedID.(primitive.ObjectID)
	if !ok {
		return nil, fmt.Errorf("InsertedID is not of type primitive.ObjectID")
	}
	user.ID = userID
	return user, nil
}

// SendEmailVerification Sends user verification email
func (service *UserService) SendEmailVerification(
	ctx context.Context,
	user *model.User,
	emailVerificationToken string,
) error {
	if err := service.emailService.SendVerificationMail(
		ctx,
		user.Email,
		user.FirstName,
		user.ID.Hex(),
		emailVerificationToken,
	); err != nil {
		return &SendEmailError{Message: "Error sending verification email"}
	}
	return nil
}

// ResendEmailVerification resends a verification email
func (service *UserService) ResendEmailVerification(
	ctx context.Context,
	user *model.User,
	emailVerificationToken string,
) error {
	if user.AccountStatus == model.AccountStatusVerified {
		return &Error{Message: EmailVerifiedError}
	}

	if err := service.emailService.SendVerificationMail(
		ctx,
		user.Email,
		user.FirstName,
		user.ID.Hex(),
		emailVerificationToken,
	); err != nil {
		return fmt.Errorf("Error sending verification email: %v", err)
	}

	return nil
}

// VerifyEmail verifies a user's email
func (service *UserService) VerifyEmail(ctx context.Context, token *model.Token) (*string, error) {
	logger, err := log.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	user, err := service.userRepository.GetByUserID(ctx, token.UserID)
	if err != nil {
		logger.Error(err, "Error getting user by ID")
		return nil, &Error{Message: InvalidTokenError}
	}
	if user.AccountStatus == model.AccountStatusVerified {
		return nil, &Error{Message: EmailVerifiedError}
	}

	user.AccountStatus = model.AccountStatusVerified

	if err := service.userRepository.UpdateStatus(ctx, user); err != nil {
		logger.Error(err, "Error updating user status")
		return nil, fmt.Errorf("Error updating user status")
	}
	return &user.Email, nil
}

// Authenticate authenticates a user and provides a token
func (service *UserService) Authenticate(ctx context.Context, email, password string) (*model.User, error) {
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

	return user, nil
}

// GetUserProfile gets a user's profile
func (service *UserService) GetUserProfile(ctx context.Context, userID string) (*model.User, error) {
	logger, err := log.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	userIDObj, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		logger.Error(err, fmt.Sprintf("Could not convert user ID %s to ObjectID", userID))
		return nil, &Error{Message: InvalidUserIDError}
	}
	user, err := service.userRepository.GetByUserID(ctx, userIDObj)
	if err != nil {
		logger.Error(err, "Error getting user by ID")
		return nil, fmt.Errorf("Error getting user by ID")
	}
	return user, nil
}

// UpdateProfileDetails updates a user's profile details
func (service *UserService) UpdateProfileDetails(
	ctx context.Context,
	userID string,
	profileDetails *pb_authentication.UpdateUserProfileRequest,
) (*model.User, error) {
	logger, err := log.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	ID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		logger.Error(err, fmt.Sprintf("Could not convert user ID %s to ObjectID", userID))
		return nil, &Error{Message: "Invalid user ID"}
	}
	updatedUser := &model.User{
		ID:          ID,
		FirstName:   profileDetails.FirstName,
		LastName:    profileDetails.LastName,
		DateOfBirth: profileDetails.DateOfBirth.AsTime(),
	}
	err = model.ValidatePartialUser(updatedUser, "FirstName", "LastName", "DateOfBirth")
	if err != nil {
		return nil, err

	}

	updatedUser, err = service.userRepository.UpdateProfileDetails(ctx, updatedUser)
	if err != nil {
		logger.Error(err, "Error getting user by ID")
		return nil, fmt.Errorf("Error getting user by ID")
	}
	return updatedUser, nil
}

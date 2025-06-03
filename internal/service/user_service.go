package service

import (
	"context"
	"fmt"
	"time"

	"github.com/quadev-ltd/qd-common/pb/gen/go/pb_authentication"
	"github.com/quadev-ltd/qd-common/pkg/log"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"

	"qd-authentication-api/internal/firebase"
	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/repository"
	"qd-authentication-api/internal/util"
)

// UserServicer is the interface for the authentication service
type UserServicer interface {
	Register(ctx context.Context, email, password, firstName, lastName string, dateOfBirth *time.Time) (*model.User, error)
	SendEmailVerification(ctx context.Context, user *model.User, emailVerificationToken string) error
	ResendEmailVerification(ctx context.Context, email *model.User, emailVerificationToken string) error
	VerifyEmail(ctx context.Context, token *model.Token) (*model.User, error)
	AuthenticateWithFirebase(ctx context.Context, idToken, email, firstName, lastName string) (*model.User, error)
	Authenticate(ctx context.Context, email, password string) (*model.User, error)
	GetUserProfile(ctx context.Context, userID string) (*model.User, error)
	GetUserByID(ctx context.Context, userID string) (*model.User, error)
	UpdateProfileDetails(ctx context.Context, userID string, profileDetails *pb_authentication.UpdateUserProfileRequest) (*model.User, error)
	DeleteUser(ctx context.Context, userID string) error
}

// UserService is the implementation of the authentication service
type UserService struct {
	emailService        EmailServicer
	firebaseAuthService firebase.AuthServicer
	userRepository      repository.UserRepositoryer
}

var _ UserServicer = &UserService{}

// NewUserService creates a new authentication service
func NewUserService(
	emailService EmailServicer,
	firebaseAuthService firebase.AuthServicer,
	userRepository repository.UserRepositoryer,
) UserServicer {
	return &UserService{
		emailService,
		firebaseAuthService,
		userRepository,
	}
}

// TODO: pass an object DTO instead of all the parameters and check input validation

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
		AuthTypes:        []model.AuthenticationType{model.PasswordAuthType},
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

	userID, ok := insertedID.(primitive.ObjectID)
	if !ok {
		return nil, fmt.Errorf("InsertedID is not of type primitive.ObjectID")
	}
	user.ID = userID
	return user, nil
}

// AuthenticateWithFirebase uses firebase idToken to authenticate/register user
func (service *UserService) AuthenticateWithFirebase(
	ctx context.Context,
	idToken,
	email,
	firstName,
	lastName string,
) (*model.User, error) {
	logger, err := log.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	googleToken, err := service.firebaseAuthService.VerifyIDToken(ctx, idToken)
	if err != nil {
		logger.Error(err, "Error verifying Firebase ID token")
		return nil, &Error{Message: FirebaseVerificationError}
	}

	emailClaim := googleToken.Claims["email"].(string)

	exists, err := service.userRepository.ExistsByEmail(ctx, emailClaim)
	if err != nil {
		logger.Error(err, "Error checking if user exists")
		return nil, fmt.Errorf("Error checking if user exists")
	}

	if !exists {
		user := &model.User{
			Email:            emailClaim,
			FirstName:        firstName,
			LastName:         lastName,
			RegistrationDate: time.Now(),
			LastLoginDate:    time.Now(),
			AccountStatus:    model.AccountStatusVerified,
			AuthTypes:        []model.AuthenticationType{model.FirebaseAuthType},
		}

		if err := model.ValidateUser(user); err != nil {
			return nil, err
		}
		insertedID, err := service.userRepository.InsertUser(ctx, user)
		if err != nil {
			logger.Error(err, "Error inserting user in DB")
			return nil, fmt.Errorf("Error storing user")
		}
		userID, ok := insertedID.(primitive.ObjectID)
		if !ok {
			return nil, fmt.Errorf("InsertedID is not of type primitive.ObjectID")
		}
		user.ID = userID
		err = service.emailService.SendAuthenticationSuccessEmail(ctx, user.Email, user.FirstName)
		if err != nil {
			logger.Error(err, "Error sending successful authentication email")
		}
		return user, nil
	}
	user, err := service.userRepository.GetByEmail(ctx, emailClaim)
	if err != nil {
		logger.Error(err, fmt.Sprintf("Error getting user by email %s", emailClaim))
		return nil, fmt.Errorf("Error getting user by email")
	}
	if !model.ContainsAuthType(user.AuthTypes, model.FirebaseAuthType) {
		authTypes := append(user.AuthTypes, model.FirebaseAuthType)
		user.AuthTypes = authTypes
		err = service.userRepository.UpdateAuthTypes(ctx, user)
		if err != nil {
			logger.Error(err, fmt.Sprintf("Error updating user %s auth type", user.Email))
			return nil, fmt.Errorf("Error updating user auth type")
		}
	}
	if user.AccountStatus != model.AccountStatusVerified {
		user.AccountStatus = model.AccountStatusVerified
		err = service.userRepository.UpdateStatus(ctx, user)
		if err != nil {
			logger.Error(err, fmt.Sprintf("Error updating user %s status", user.Email))
			return nil, fmt.Errorf("Error updating user status")
		}
	}
	err = service.emailService.SendAuthenticationSuccessEmail(ctx, user.Email, user.FirstName)
	if err != nil {
		logger.Error(err, "Error sending successful authentication email")
	}
	return user, nil
}

// SendEmailVerification Sends user verification email
func (service *UserService) SendEmailVerification(
	ctx context.Context,
	user *model.User,
	emailVerificationToken string,
) error {
	if err := service.emailService.SendVerificationEmail(
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

	if err := service.emailService.SendVerificationEmail(
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
func (service *UserService) VerifyEmail(ctx context.Context, token *model.Token) (*model.User, error) {
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
	if err := service.emailService.SendVerificationSuccessEmail(
		ctx,
		user.Email,
		user.FirstName,
	); err != nil {
		return nil, err
	}
	return user, nil
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
	usesPasswordAuth := model.ContainsAuthType(user.AuthTypes, model.PasswordAuthType)
	if !usesPasswordAuth {
		return nil, &model.WrongEmailOrPassword{FieldName: "AuthType"}
	}

	resultError = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password+user.PasswordSalt))
	if resultError != nil {
		return nil, &model.WrongEmailOrPassword{FieldName: "Password"}
	}

	err = service.emailService.SendAuthenticationSuccessEmail(ctx, user.Email, user.FirstName)
	if err != nil {
		logger.Error(err, "Error sending successful authentication email")
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

// GetUserByID gets a user by their ID
func (service *UserService) GetUserByID(ctx context.Context, userID string) (*model.User, error) {
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

// DeleteUser deletes a user
func (service *UserService) DeleteUser(
	ctx context.Context,
	userID string,
) error {
	logger, err := log.GetLoggerFromContext(ctx)
	if err != nil {
		return err
	}
	id, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		logger.Error(err, fmt.Sprintf("Could not convert user ID %s to ObjectID", userID))
		return &Error{Message: "Invalid user ID"}
	}
	user, err := service.userRepository.GetByUserID(ctx, id)
	if err != nil {
		logger.Error(err, fmt.Sprintf("User ID %s does not exist", id.Hex()))
		return fmt.Errorf("Error deleting user by ID")
	}
	err = service.userRepository.DeleteByUserID(ctx, id)
	if err != nil {
		logger.Error(err, "Error deleting user by ID")
		return fmt.Errorf("Error deleting user by ID")
	}

	err = service.emailService.SendDeletedUserEmail(ctx, user.Email, user.FirstName)
	if err != nil {
		logger.Error(err, fmt.Sprintf("Error sending delete success notification email to user ID %s", user.ID.Hex()))
	}
	return nil
}

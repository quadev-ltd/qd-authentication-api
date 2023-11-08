package service

import (
	"context"
	"fmt"
	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/repository"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// TODO: Analyse best expiry times for tokens
// Expiry times for tokens
const (
	AuthenticationTokenExpiry = 2 * time.Hour      // Authentication token expiry set to 2 hours
	RefreshTokenExpiry        = 7 * 24 * time.Hour // Refresh token expiry set to 7 days
	VerificationTokenExpiry   = 24 * time.Hour     // Verification token expiry set to 24 hours
)

// AuthenticationServicer is the interface for the authentication service
type AuthenticationServicer interface {
	GetPublicKey(ctx context.Context) (string, error)
	Register(ctx context.Context, email, password, firstName, lastName string, dateOfBirth *time.Time) error
	VerifyEmail(ctx context.Context, verificationToken string) error
	Authenticate(ctx context.Context, email, password string) (*model.AuthTokensResponse, error)
	VerifyTokenAndDecodeEmail(ctx context.Context, token string) (*string, error)
	ResendEmailVerification(ctx context.Context, email string) error
}

// AuthenticationService is the implementation of the authentication service
type AuthenticationService struct {
	emailService     EmailServicer
	userRepository   repository.UserRepositoryer
	jwtAuthenticator JWTAthenticatorer
}

var _ AuthenticationServicer = &AuthenticationService{}

// NewAuthenticationService creates a new authentication service
func NewAuthenticationService(
	emailService EmailServicer,
	userRepository repository.UserRepositoryer,
	jwtAuthenticator JWTAthenticatorer,
) AuthenticationServicer {
	return &AuthenticationService{
		userRepository:   userRepository,
		emailService:     emailService,
		jwtAuthenticator: jwtAuthenticator,
	}
}

// GetPublicKey ctx context.Contextgets the public key
func (service *AuthenticationService) GetPublicKey(ctx context.Context) (string, error) {
	return service.jwtAuthenticator.GetPublicKey(ctx)
}

// TODO pass an object DTO instead of all the parameters
// Register registers a new user
func (service *AuthenticationService) Register(ctx context.Context, email, password, firstName, lastName string, dateOfBirth *time.Time) error {
	existingUser, err := service.userRepository.GetByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("Error getting user by email: %v", err)
	}
	if existingUser != nil {
		return &model.EmailInUseError{Email: email}
	}

	hashedPassword, salt, err := generateHash(password)
	if err != nil {
		return fmt.Errorf("Error generating password hash: %v", err)
	}

	verificationToken, err := generateVerificationToken()
	if err != nil {
		return fmt.Errorf("Error generating verification token: %v", err)
	}

	verificationTokentExpiryDate := time.Now().Add(VerificationTokenExpiry)

	user := &model.User{
		Email:                       email,
		VerificationToken:           verificationToken,
		VerificationTokenExpiryDate: verificationTokentExpiryDate,
		PasswordHash:                string(hashedPassword),
		PasswordSalt:                *salt,
		FirstName:                   firstName,
		LastName:                    lastName,
		DateOfBirth:                 *dateOfBirth,
		RegistrationDate:            time.Now(),
		AccountStatus:               model.AccountStatusUnverified,
	}

	// Validate the user object
	if err := model.ValidateUser(user); err != nil {
		return err
	}

	// Create the user in the repository
	if err := service.userRepository.Create(ctx, user); err != nil {
		return fmt.Errorf("Error creating user: %v", err)
	}

	if err := service.emailService.SendVerificationMail(ctx, user.Email, user.FirstName, user.VerificationToken); err != nil {
		return fmt.Errorf("Error sending verification email: %v", err)
	}

	return nil
}

// VerifyEmail verifies a user's email
func (service *AuthenticationService) VerifyEmail(ctx context.Context, verificationToken string) error {
	user, err := service.userRepository.GetByVerificationToken(ctx, verificationToken)
	if err != nil {
		return fmt.Errorf("Error getting user by verification token: %v", err)
	}
	if user == nil {
		return &Error{Message: "Invalid verification token"}
	}
	if user.AccountStatus == model.AccountStatusVerified {
		return &Error{Message: "Email already verified"}
	}
	current := time.Now()
	timeDifference := current.Sub(user.VerificationTokenExpiryDate)
	if timeDifference >= VerificationTokenExpiry {
		return &Error{Message: "Verification token expired"}
	}
	user.AccountStatus = model.AccountStatusVerified

	if err := service.userRepository.Update(ctx, user); err != nil {
		return fmt.Errorf("Error updating user: %v", err)
	}

	return nil
}

// Authenticate authenticates a user and provides a token
func (service *AuthenticationService) Authenticate(ctx context.Context, email, password string) (*model.AuthTokensResponse, error) {
	user, resultError := service.userRepository.GetByEmail(ctx, email)
	if resultError != nil {
		return nil, fmt.Errorf("Error getting user by email: %v", resultError)
	}

	if user == nil {
		return nil, &model.WrongEmailOrPassword{FieldName: "Email"}
	}

	resultError = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password+user.PasswordSalt))
	if resultError != nil {
		return nil, &model.WrongEmailOrPassword{FieldName: "Password"}
	}

	authenticationTokenExpiryDate := time.Now().Add(AuthenticationTokenExpiry)
	authTokenString, err := service.jwtAuthenticator.SignToken(user.Email, authenticationTokenExpiryDate)
	if err != nil {
		return nil, &Error{
			Message: "Error creating authentication token",
		}
	}

	refreshTokenExpiration := time.Now().Add(RefreshTokenExpiry)
	refreshTokenString, err := service.jwtAuthenticator.SignToken(user.Email, refreshTokenExpiration)
	if err != nil {
		return nil, &Error{
			Message: "Error creating refresh token",
		}
	}

	response := &model.AuthTokensResponse{
		AuthToken:          *authTokenString,
		AuthTokenExpiry:    authenticationTokenExpiryDate,
		RefreshToken:       *refreshTokenString,
		RefreshTokenExpiry: refreshTokenExpiration,
		UserEmail:          user.Email,
	}

	return response, nil
}

// VerifyTokenAndDecodeEmail verifies a token and decodes the email
func (service *AuthenticationService) VerifyTokenAndDecodeEmail(
	ctx context.Context,
	token string,
) (*string, error) {
	jwtToken, err := service.jwtAuthenticator.VerifyToken(token)
	if err != nil {
		return nil, fmt.Errorf("Error verifying token: %v", err)
	}
	email, err := service.jwtAuthenticator.GetEmailFromToken(jwtToken)
	if err != nil {
		return nil, fmt.Errorf("Error getting email from token: %v", err)
	}
	return email, nil
}

// ResendEmailVerification resends a verification email
func (service *AuthenticationService) ResendEmailVerification(
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

	verificationToken, err := generateVerificationToken()
	if err != nil {
		return fmt.Errorf("Error generating verification token: %v", err)
	}
	user.VerificationToken = verificationToken
	user.VerificationTokenExpiryDate = time.Now().Add(VerificationTokenExpiry)

	if err := service.userRepository.Update(ctx, user); err != nil {
		return fmt.Errorf("Error updating user: %v", err)
	}

	if err := service.emailService.SendVerificationMail(
		ctx,
		user.Email,
		user.FirstName,
		user.VerificationToken,
	); err != nil {
		return fmt.Errorf("Error sending verification email: %v", err)
	}

	return nil
}

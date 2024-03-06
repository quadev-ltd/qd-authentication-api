package service

import (
	"context"
	"fmt"
	"time"

	commonJWT "github.com/quadev-ltd/qd-common/pkg/jwt"
	"github.com/quadev-ltd/qd-common/pkg/log"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"

	"qd-authentication-api/internal/jwt"
	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/repository"
	"qd-authentication-api/internal/util"
)

// TODO: Analyse best expiry times for tokens
// Expiry times for tokens
const (
	AuthenticationTokenExpiry = 2 * time.Hour      // Authentication token expiry set to 2 hours
	RefreshTokenExpiry        = 7 * 24 * time.Hour // Refresh token expiry set to 7 days
	VerificationTokenExpiry   = 24 * time.Hour     // Verification token expiry set to 24 hours
	PasswordResetTokenExpiry  = 20 * time.Minute
	RefreshTokenRenewalWindow = 12 * time.Hour // Refresh token renewal set to 7 days
)

// AuthenticationServicer is the interface for the authentication service
type AuthenticationServicer interface {
	GetPublicKey(ctx context.Context) (string, error)
	Register(ctx context.Context, email, password, firstName, lastName string, dateOfBirth *time.Time) error
	VerifyEmail(ctx context.Context, verificationToken string) error
	Authenticate(ctx context.Context, email, password string) (*model.AuthTokensResponse, error)
	VerifyTokenAndDecodeEmail(ctx context.Context, token string) (*string, error)
	ResendEmailVerification(ctx context.Context, email string) error
	RefreshToken(ctx context.Context, refreshTokenString string) (*model.AuthTokensResponse, error)
	ForgotPassword(ctx context.Context, email string) error
	VerifyResetPasswordToken(ctx context.Context, token string) error
	ResetPassword(ctx context.Context, token, password string) error
}

// AuthenticationService is the implementation of the authentication service
type AuthenticationService struct {
	emailService     EmailServicer
	userRepository   repository.UserRepositoryer
	tokenRepository  repository.TokenRepositoryer
	jwtAuthenticator jwt.Managerer
}

var _ AuthenticationServicer = &AuthenticationService{}

// NewAuthenticationService creates a new authentication service
func NewAuthenticationService(
	emailService EmailServicer,
	userRepository repository.UserRepositoryer,
	tokenRepository repository.TokenRepositoryer,
	jwtAuthenticator jwt.Managerer,
) AuthenticationServicer {
	return &AuthenticationService{
		emailService,
		userRepository,
		tokenRepository,
		jwtAuthenticator,
	}
}

// GetPublicKey ctx context.Contextgets the public key
func (service *AuthenticationService) GetPublicKey(ctx context.Context) (string, error) {
	return service.jwtAuthenticator.GetPublicKey(ctx)
}

// TODO pass an object DTO instead of all the parameters and check input validation

// Register registers a new user
func (service *AuthenticationService) Register(ctx context.Context, email, password, firstName, lastName string, dateOfBirth *time.Time) error {
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
	verificationToken, err := util.GenerateVerificationToken()
	if err != nil {
		return fmt.Errorf("Error generating verification token: %v", err)
	}
	verificationTokentExpiryDate := time.Now().Add(VerificationTokenExpiry)
	emailVerificationToken := &model.Token{
		UserID:    userID,
		Token:     verificationToken,
		ExpiresAt: verificationTokentExpiryDate,
		Type:      commonJWT.EmailVerificationTokenType,
		IssuedAt:  time.Now(),
	}
	_, err = service.tokenRepository.InsertToken(ctx, emailVerificationToken)
	if err != nil {
		return fmt.Errorf("Error inserting verification token in DB: %v", err)
	}

	if err := service.emailService.SendVerificationMail(ctx, user.Email, user.FirstName, verificationToken); err != nil {
		logger.Error(err, "Error sending verification email")
		return &SendEmailError{Message: "Error sending verification email"}
	}

	return nil
}

// VerifyEmail verifies a user's email
func (service *AuthenticationService) VerifyEmail(ctx context.Context, verificationToken string) error {
	token, err := service.tokenRepository.GetByToken(ctx, verificationToken)
	if err != nil {
		return &Error{Message: "Invalid verification token"}
	}
	if token.Type != commonJWT.EmailVerificationTokenType {
		return &Error{Message: "Wrong type of token"}
	}
	current := time.Now()
	timeDifference := current.Sub(token.ExpiresAt)
	if timeDifference >= 0 {
		return &Error{Message: "Verification token expired"}
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

	err = service.tokenRepository.Remove(ctx, token.Token)
	if err != nil {
		return fmt.Errorf("Error removing token: %v", err)
	}
	return nil
}

func (service *AuthenticationService) createToken(ctx context.Context, email string, expiry time.Duration, tokenType commonJWT.TokenType) (*string, *time.Time, error) {
	logger, err := log.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	tokenExpiryDate := time.Now().Add(expiry)
	tokenString, err := service.jwtAuthenticator.SignToken(email, tokenExpiryDate, tokenType)
	if err != nil {
		logger.Error(err, "Error creating jwt token")
		return nil, nil, &Error{
			Message: "Error creating jwt token",
		}
	}
	return tokenString, &tokenExpiryDate, nil
}

func (service *AuthenticationService) createTokenResponse(
	ctx context.Context,
	user *model.User,
	refreshToken *string,
) (*model.AuthTokensResponse, error) {
	authTokenString,
		authenticationTokenExpiration,
		err := service.createToken(ctx, user.Email, AuthenticationTokenExpiry, commonJWT.AccessTokenType)
	if err != nil {
		return nil, &Error{
			Message: "Error creating authentication token",
		}
	}

	refreshTokenString,
		refreshTokenExpiration,
		err := service.createToken(ctx, user.Email, RefreshTokenExpiry, commonJWT.RefreshTokenType)
	if err != nil {
		return nil, &Error{
			Message: "Error creating refresh token",
		}
	}

	newRefreshToken := model.Token{
		Token:     *refreshTokenString,
		IssuedAt:  time.Now(),
		ExpiresAt: *refreshTokenExpiration,
		Revoked:   false,
		Type:      commonJWT.RefreshTokenType,
		UserID:    user.ID,
	}

	shouldReplaceExistingToken := refreshToken != nil
	if shouldReplaceExistingToken {
		err = service.tokenRepository.Remove(ctx, *refreshToken)
		if err != nil {
			return nil, fmt.Errorf("Refresh token is not listed in DB: %v", err)
		}

	}
	_, err = service.tokenRepository.InsertToken(ctx, &newRefreshToken)
	if err != nil {
		return nil, fmt.Errorf("Could not insert new refresh token in DB: %v", err)
	}

	return &model.AuthTokensResponse{
		AuthToken:          *authTokenString,
		AuthTokenExpiry:    *authenticationTokenExpiration,
		RefreshToken:       *refreshTokenString,
		RefreshTokenExpiry: *refreshTokenExpiration,
		UserEmail:          user.Email,
	}, nil
}

// Authenticate authenticates a user and provides a token
func (service *AuthenticationService) Authenticate(ctx context.Context, email, password string) (*model.AuthTokensResponse, error) {
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

	return service.createTokenResponse(ctx, user, nil)
}

// VerifyTokenAndDecodeEmail verifies decodes the email from the jwt token
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

	verificationToken, err := util.GenerateVerificationToken()
	if err != nil {
		return fmt.Errorf("Error generating verification token: %v", err)
	}
	emailVerificationToken := &model.Token{
		Token:     verificationToken,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now(),
		Revoked:   false,
		Type:      commonJWT.EmailVerificationTokenType,
		UserID:    user.ID,
	}
	_, err = service.tokenRepository.InsertToken(ctx, emailVerificationToken)
	if err != nil {
		return fmt.Errorf("Error inserting the verification token in db: %v", err)
	}

	if err := service.emailService.SendVerificationMail(
		ctx,
		user.Email,
		user.FirstName,
		verificationToken,
	); err != nil {
		return fmt.Errorf("Error sending verification email: %v", err)
	}

	return nil
}

// RefreshToken refreshes an authentication token using a refresh token
func (service *AuthenticationService) RefreshToken(ctx context.Context, refreshTokenString string) (*model.AuthTokensResponse, error) {
	logger, err := log.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	// Verify the refresh token
	token, err := service.jwtAuthenticator.VerifyToken(refreshTokenString)
	if err != nil {
		logger.Error(err, "Error verifying refresh token")
		return nil, &Error{
			Message: "Invalid or expired refresh token",
		}
	}

	email, err := service.jwtAuthenticator.GetEmailFromToken(token)
	if err != nil {
		logger.Error(err, "Error getting email from token")
		return nil, &Error{
			Message: "Error getting email from token",
		}
	}

	// Retrieve user details from the database
	user, err := service.userRepository.GetByEmail(ctx, *email)
	if err != nil {
		logger.Error(err, "Error getting user by email")
		return nil, &Error{
			Message: "Error getting user by email",
		}
	}

	return service.createTokenResponse(ctx, user, &refreshTokenString)
}

// ForgotPassword sends a password reset email
func (service *AuthenticationService) ForgotPassword(ctx context.Context, email string) error {
	user, err := service.userRepository.GetByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("Error getting user by email: %v", err)
	}
	if user.AccountStatus == model.AccountStatusUnverified {
		return &Error{Message: fmt.Sprintf("Email account %s not verified yet", email)}
	}
	resetToken, err := util.GenerateVerificationToken()
	if err != nil {
		return fmt.Errorf("Error generating reset token: %v", err)
	}
	token := &model.Token{
		UserID:    user.ID,
		Token:     resetToken,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(PasswordResetTokenExpiry),
		Revoked:   false,
		Type:      commonJWT.ResetPasswordTokenType,
	}
	_, err = service.tokenRepository.InsertToken(ctx, token)
	if err != nil {
		return fmt.Errorf("Error inserting token in db: %v", err)
	}
	if err := service.emailService.SendPasswordResetMail(ctx, user.Email, user.FirstName, resetToken); err != nil {
		return fmt.Errorf("Error sending password reset email: %v", err)
	}
	return nil
}

func (service *AuthenticationService) verifyResetPasswordTokenValidity(ctx context.Context, tokenValue string) (*model.Token, error) {
	token, err := service.tokenRepository.GetByToken(ctx, tokenValue)
	if err != nil {
		return nil, fmt.Errorf("Error getting token by its value: %v", err)
	}
	if token.Type != commonJWT.ResetPasswordTokenType {
		return nil, &Error{Message: "Invalid token type"}
	}
	current := time.Now()
	timeDifference := current.Sub(token.ExpiresAt)
	if timeDifference >= 0 {
		return nil, &Error{Message: "Token expired"}
	}
	return token, nil
}

// VerifyResetPasswordToken verifies a password reset token validity
func (service *AuthenticationService) VerifyResetPasswordToken(ctx context.Context, tokenValue string) error {
	_, err := service.verifyResetPasswordTokenValidity(ctx, tokenValue)
	if err != nil {
		return err
	}
	return nil
}

// ResetPassword resets the user password
func (service *AuthenticationService) ResetPassword(ctx context.Context, tokenValue, password string) error {
	token, err := service.verifyResetPasswordTokenValidity(ctx, tokenValue)
	if err != nil {
		return err
	}
	user, err := service.userRepository.GetByUserID(ctx, token.UserID)
	if err != nil {
		return fmt.Errorf("Error getting user assigned to the token: %v", err)
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
	user.PasswordHash = string(hashedPassword)
	user.PasswordSalt = *salt
	if err := service.userRepository.UpdatePassword(ctx, user); err != nil {
		return fmt.Errorf("Error updating user: %v", err)
	}
	return nil
}

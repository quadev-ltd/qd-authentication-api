package service

import (
	"context"
	"fmt"
	"time"

	commonJWT "github.com/quadev-ltd/qd-common/pkg/jwt"
	"github.com/quadev-ltd/qd-common/pkg/log"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"qd-authentication-api/internal/jwt"
	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/repository"
	"qd-authentication-api/internal/util"
)

// TokenServicer is the interface for the authentication service
type TokenServicer interface {
	GetPublicKey(ctx context.Context) (string, error)
	GenerateJWTToken(ctx context.Context, email string, expiry time.Duration, tokenType commonJWT.TokenType) (*string, *time.Time, error)
	GenerateJWTTokens(ctx context.Context, user *model.User, refreshToken *string) (*model.AuthTokensResponse, error)
	GenerateEmailVerificationToken(ctx context.Context, userID primitive.ObjectID) (*string, error)
	GeneratePasswordResetToken(ctx context.Context, userID primitive.ObjectID) (*string, error)
	VerifyJWTToken(ctx context.Context, refreshTokenString string) (*jwt.TokenClaims, error)
	VerifyResetPasswordToken(ctx context.Context, token string) (*model.Token, error)
	VerifyEmailVerificationToken(ctx context.Context, token string) (*model.Token, error)
	RemoveUsedToken(ctx context.Context, token string) error
}

// TokenService is the implementation of the authentication service
type TokenService struct {
	tokenRepository repository.TokenRepositoryer
	jwtManager      jwt.Managerer
}

var _ TokenServicer = &TokenService{}

// NewTokenService creates a new authentication service
func NewTokenService(
	tokenRepository repository.TokenRepositoryer,
	jwtManager jwt.Managerer,
) TokenServicer {
	return &TokenService{
		tokenRepository,
		jwtManager,
	}
}

// TODO: pass an object DTO instead of all the parameters and check input validation
// TODO: Inject GenerateVerificationToken or use JWT tokens
func (service *TokenService) generateVerificationToken(
	ctx context.Context,
	userID primitive.ObjectID,
	tokenType commonJWT.TokenType,
) (*string, error) {
	verificationToken, err := util.GenerateVerificationToken()
	if err != nil {
		return nil, fmt.Errorf("Error generating verification token: %v", err)
	}
	verificationTokentExpiryDate := time.Now().Add(VerificationTokenExpiry)
	emailVerificationToken := &model.Token{
		UserID:    userID,
		Token:     verificationToken,
		ExpiresAt: verificationTokentExpiryDate,
		Type:      tokenType,
		IssuedAt:  time.Now(),
	}
	_, err = service.tokenRepository.InsertToken(ctx, emailVerificationToken)
	if err != nil {
		return nil, fmt.Errorf("Error inserting verification token in DB: %v", err)
	}
	return &verificationToken, nil
}

// GenerateEmailVerificationToken generates an email verification token
func (service *TokenService) GenerateEmailVerificationToken(ctx context.Context, userID primitive.ObjectID) (*string, error) {
	return service.generateVerificationToken(ctx, userID, commonJWT.EmailVerificationTokenType)
}

// GeneratePasswordResetToken generates an email verification token
func (service *TokenService) GeneratePasswordResetToken(ctx context.Context, userID primitive.ObjectID) (*string, error) {
	return service.generateVerificationToken(ctx, userID, commonJWT.ResetPasswordTokenType)
}

// RemoveUsedToken removes a token from the database
func (service *TokenService) RemoveUsedToken(ctx context.Context, token string) error {
	err := service.tokenRepository.Remove(ctx, token)
	if err != nil {
		return fmt.Errorf("Error removing token: %v", err)
	}
	return nil
}

// GetPublicKey ctx context.Contextgets the public key
func (service *TokenService) GetPublicKey(ctx context.Context) (string, error) {
	return service.jwtManager.GetPublicKey(ctx)
}

// GenerateJWTToken creates a jwt token
func (service *TokenService) GenerateJWTToken(
	ctx context.Context,
	email string,
	expiry time.Duration,
	tokenType commonJWT.TokenType,
) (*string, *time.Time, error) {
	logger, err := log.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	tokenExpiryDate := time.Now().Add(expiry)
	tokenString, err := service.jwtManager.SignToken(email, tokenExpiryDate, tokenType)
	if err != nil {
		logger.Error(err, "Error creating jwt token")
		return nil, nil, &Error{
			Message: "Error creating jwt token",
		}
	}
	return tokenString, &tokenExpiryDate, nil
}

// GenerateJWTTokens creates a jwt access and refresh token
func (service *TokenService) GenerateJWTTokens(
	ctx context.Context,
	user *model.User,
	refreshToken *string,
) (*model.AuthTokensResponse, error) {
	authTokenString,
		authenticationTokenExpiration,
		err := service.GenerateJWTToken(ctx, user.Email, AuthenticationTokenExpiry, commonJWT.AccessTokenType)
	if err != nil {
		return nil, &Error{
			Message: "Error creating authentication token",
		}
	}

	refreshTokenString,
		refreshTokenExpiration,
		err := service.GenerateJWTToken(ctx, user.Email, RefreshTokenExpiry, commonJWT.RefreshTokenType)
	if err != nil {
		return nil, &Error{
			Message: "Error creating refresh token",
		}
	}

	newRefreshToken := &model.Token{
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
	_, err = service.tokenRepository.InsertToken(ctx, newRefreshToken)
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

// VerifyJWTToken refreshes an authentication token using a refresh token
func (service *TokenService) VerifyJWTToken(
	ctx context.Context,
	tokenValue string,
) (*jwt.TokenClaims, error) {
	logger, err := log.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	// Verify the refresh token
	token, err := service.jwtManager.VerifyToken(tokenValue)
	if err != nil {
		logger.Error(err, "Error verifying refresh token")
		return nil, &Error{
			Message: "Invalid or expired refresh token",
		}
	}

	claims, err := service.jwtManager.GetClaimsFromToken(token)
	if err != nil {
		logger.Error(err, "Error getting claims from token")
		return nil, &Error{
			Message: "Error getting claims from token",
		}
	}
	return claims, nil
}

// VerifyTokenValidity verifies a token validity
func (service *TokenService) VerifyTokenValidity(ctx context.Context, tokenValue string, tokenType commonJWT.TokenType) (*model.Token, error) {
	logger, err := log.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	token, err := service.tokenRepository.GetByToken(ctx, tokenValue)
	if err != nil {
		logger.Error(err, "Error getting token by its value")
		return nil, &Error{Message: "Invalid token"}
	}
	if token.Type != tokenType {
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
func (service *TokenService) VerifyResetPasswordToken(ctx context.Context, tokenValue string) (*model.Token, error) {
	token, err := service.VerifyTokenValidity(ctx, tokenValue, commonJWT.ResetPasswordTokenType)
	if err != nil {
		return nil, err
	}
	return token, nil
}

// VerifyEmailVerificationToken verifies an email verification token validity
func (service *TokenService) VerifyEmailVerificationToken(ctx context.Context, tokenValue string) (*model.Token, error) {
	token, err := service.VerifyTokenValidity(ctx, tokenValue, commonJWT.EmailVerificationTokenType)
	if err != nil {
		return nil, err
	}
	return token, nil
}

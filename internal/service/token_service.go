package service

import (
	"context"
	"fmt"

	"github.com/quadev-ltd/qd-common/pkg/log"
	commonLogger "github.com/quadev-ltd/qd-common/pkg/log"
	commonToken "github.com/quadev-ltd/qd-common/pkg/token"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"qd-authentication-api/internal/jwt"
	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/repository"
	"qd-authentication-api/internal/util"
)

// TokenServicer is the interface for the authentication service
type TokenServicer interface {
	GetPublicKey(ctx context.Context) (string, error)
	GenerateJWTToken(ctx context.Context, claims *jwt.TokenClaims) (*string, error)
	GenerateJWTTokens(ctx context.Context, userEmail, userID string) (*model.AuthTokensResponse, error)
	GenerateEmailVerificationToken(ctx context.Context, userID primitive.ObjectID) (*string, error)
	GeneratePasswordResetToken(ctx context.Context, userID primitive.ObjectID) (*string, error)
	VerifyJWTToken(ctx context.Context, refreshTokenString string) (*jwt.TokenClaims, error)
	VerifyResetPasswordToken(ctx context.Context, token string) (*model.Token, error)
	VerifyEmailVerificationToken(ctx context.Context, token string) (*model.Token, error)
	RemoveUsedToken(ctx context.Context, token *model.Token) error
}

// TokenService is the implementation of the authentication service
type TokenService struct {
	tokenRepository repository.TokenRepositoryer
	jwtManager      jwt.Managerer
	timeProvider    util.TimeProvider
}

var _ TokenServicer = &TokenService{}

// NewTokenService creates a new authentication service
func NewTokenService(
	tokenRepository repository.TokenRepositoryer,
	jwtManager jwt.Managerer,
	timeProvider util.TimeProvider,
) TokenServicer {
	return &TokenService{
		tokenRepository,
		jwtManager,
		timeProvider,
	}
}

// TODO: pass an object DTO instead of all the parameters and check input validation
// TODO: Inject GenerateVerificationToken or use JWT tokens
func (service *TokenService) generateVerificationToken(
	ctx context.Context,
	userID primitive.ObjectID,
	tokenType commonToken.TokenType,
) (*string, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	verificationToken, err := util.GenerateVerificationToken()
	if err != nil {
		logger.Error(err, "Error generating verification token")
		return nil, &Error{Message: "Error generating verification token"}
	}
	tokenHash, salt, err := util.GenerateHash(verificationToken, false)
	if err != nil {
		logger.Error(err, "Error hashing verification token")
		return nil, &Error{Message: "Error hashing verification token"}
	}
	verificationTokentExpiryDate := service.timeProvider.Now().Add(VerificationTokenExpiry)
	emailVerificationToken := &model.Token{
		UserID:    userID,
		TokenHash: string(tokenHash),
		Salt:      *salt,
		ExpiresAt: verificationTokentExpiryDate,
		Type:      tokenType,
		IssuedAt:  service.timeProvider.Now(),
	}
	_, err = service.tokenRepository.InsertToken(ctx, emailVerificationToken)
	if err != nil {
		logger.Error(err, "Error inserting verification token in DB")
		return nil, fmt.Errorf("Error storing verification token")
	}
	return &verificationToken, nil
}

// GenerateEmailVerificationToken generates an email verification token
func (service *TokenService) GenerateEmailVerificationToken(ctx context.Context, userID primitive.ObjectID) (*string, error) {
	return service.generateVerificationToken(ctx, userID, commonToken.EmailVerificationTokenType)
}

// GeneratePasswordResetToken generates an email verification token
func (service *TokenService) GeneratePasswordResetToken(ctx context.Context, userID primitive.ObjectID) (*string, error) {
	return service.generateVerificationToken(ctx, userID, commonToken.ResetPasswordTokenType)
}

// RemoveUsedToken removes a token from the database
func (service *TokenService) RemoveUsedToken(ctx context.Context, token *model.Token) error {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return err
	}
	err = service.tokenRepository.Remove(ctx, token)
	if err != nil {
		logger.Error(err, "Error removing token")
		return &Error{Message: "Could not remove old token"}
	}
	return nil
}

// GetPublicKey ctx context.Contextgets the public key
func (service *TokenService) GetPublicKey(ctx context.Context) (string, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return "", err
	}
	key, err := service.jwtManager.GetPublicKey(ctx)
	if err != nil {
		logger.Error(err, "Error getting public key")
		return "", &Error{Message: "Error getting public key"}
	}
	return key, nil
}

// GenerateJWTToken creates a jwt token
func (service *TokenService) GenerateJWTToken(
	ctx context.Context,
	claims *jwt.TokenClaims,
) (*string, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	tokenString, err := service.jwtManager.SignToken(claims)
	if err != nil {
		logger.Error(err, "Error creating jwt token")
		return nil, &Error{
			Message: "Error creating jwt token",
		}
	}
	return tokenString, nil
}

// GenerateJWTTokens creates a jwt access and refresh token
func (service *TokenService) GenerateJWTTokens(
	ctx context.Context,
	userEmail,
	userID string,
) (*model.AuthTokensResponse, error) {
	// Access token creation
	authenticationTokenExpiration := service.timeProvider.Now().Add(AuthenticationTokenDuration)
	accessTokenClaims := &jwt.TokenClaims{
		Email:  userEmail,
		UserID: userID,
		Type:   commonToken.AccessTokenType,
		Expiry: authenticationTokenExpiration,
	}
	authTokenString, err := service.GenerateJWTToken(ctx, accessTokenClaims)
	if err != nil {
		return nil, fmt.Errorf("Error creating authentication token: %v", err)
	}

	// Refresh token creation
	refreshTokenExpiration := service.timeProvider.Now().Add(RefreshTokenDuration)
	refreshTokenClaims := &jwt.TokenClaims{
		Email:  userEmail,
		UserID: userID,
		Type:   commonToken.RefreshTokenType,
		Expiry: refreshTokenExpiration,
	}
	refreshTokenString, err := service.GenerateJWTToken(ctx, refreshTokenClaims)
	if err != nil {
		return nil, fmt.Errorf("Error creating refresh token: %v", err)
	}

	return &model.AuthTokensResponse{
		AuthToken:          *authTokenString,
		AuthTokenExpiry:    authenticationTokenExpiration,
		RefreshToken:       *refreshTokenString,
		RefreshTokenExpiry: refreshTokenExpiration,
		UserEmail:          userEmail,
		UserID:             userID,
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

// VerifyTokenValidity verifies a email verification or password reset token validity
func (service *TokenService) VerifyTokenValidity(ctx context.Context, tokenValue string, tokenType commonToken.TokenType) (*model.Token, error) {
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
	current := service.timeProvider.Now()
	timeDifference := current.Sub(token.ExpiresAt)
	if timeDifference >= 0 {
		return nil, &Error{Message: "Token expired"}
	}
	return token, nil
}

// VerifyResetPasswordToken verifies a password reset token validity
func (service *TokenService) VerifyResetPasswordToken(ctx context.Context, tokenValue string) (*model.Token, error) {
	token, err := service.VerifyTokenValidity(ctx, tokenValue, commonToken.ResetPasswordTokenType)
	if err != nil {
		return nil, err
	}
	return token, nil
}

// VerifyEmailVerificationToken verifies an email verification token validity
func (service *TokenService) VerifyEmailVerificationToken(ctx context.Context, tokenValue string) (*model.Token, error) {
	token, err := service.VerifyTokenValidity(ctx, tokenValue, commonToken.EmailVerificationTokenType)
	if err != nil {
		return nil, err
	}
	return token, nil
}

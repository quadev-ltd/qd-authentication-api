package service

import (
	"context"
	"fmt"
	"time"

	commonJWT "github.com/quadev-ltd/qd-common/pkg/jwt"
	commonLogger "github.com/quadev-ltd/qd-common/pkg/log"
	commonToken "github.com/quadev-ltd/qd-common/pkg/token"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"

	"qd-authentication-api/internal/firebase"
	"qd-authentication-api/internal/jwt"
	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/repository"
	"qd-authentication-api/internal/util"
)

// TokenServicer is the interface for the authentication service
type TokenServicer interface {
	GetPublicKey(ctx context.Context) (string, error)
	GenerateJWTToken(ctx context.Context, claims *commonJWT.TokenClaims) (*string, error)
	GenerateJWTTokens(ctx context.Context, userEmail, userID string, includeFirebaseToken bool) (*model.AuthTokensResponse, error)
	GenerateEmailVerificationToken(ctx context.Context, userID primitive.ObjectID) (*string, error)
	GeneratePasswordResetToken(ctx context.Context, userID primitive.ObjectID) (*string, error)
	VerifyJWTToken(ctx context.Context, refreshTokenString string) (*commonJWT.TokenClaims, error)
	VerifyResetPasswordToken(ctx context.Context, userID, token string) (*model.Token, error)
	VerifyEmailVerificationToken(ctx context.Context, userID, token string) (*model.Token, error)
	RemoveUsedToken(ctx context.Context, token *model.Token) error
	RemoveUnusedTokens(ctx context.Context, userID string, tokenType commonToken.Type) error
}

// TokenService is the implementation of the authentication service
type TokenService struct {
	tokenRepository repository.TokenRepositoryer
	jwtManager      jwt.Managerer
	timeProvider    util.TimeProvider
	firebaseService firebase.AuthServicer
}

var _ TokenServicer = &TokenService{}

// NewTokenService creates a new authentication service
func NewTokenService(
	tokenRepository repository.TokenRepositoryer,
	jwtManager jwt.Managerer,
	timeProvider util.TimeProvider,
	firebaseService firebase.AuthServicer,
) TokenServicer {
	return &TokenService{
		tokenRepository,
		jwtManager,
		timeProvider,
		firebaseService,
	}
}

// TODO: Inject GenerateVerificationToken or use JWT tokens
func (service *TokenService) generateVerificationToken(
	ctx context.Context,
	userID primitive.ObjectID,
	tokenType commonToken.Type,
) (*string, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	err = service.RemoveUnusedTokens(ctx, userID.Hex(), tokenType)
	if err != nil {
		return nil, err
	}
	verificationToken, err := util.GenerateVerificationToken()
	if err != nil {
		logger.Error(err, "Error generating verification token")
		return nil, &Error{Message: "Error generating verification token"}
	}
	tokenHash, _, err := util.GenerateHash(verificationToken, false)
	if err != nil {
		logger.Error(err, "Error hashing verification token")
		return nil, fmt.Errorf("Error hashing verification token")
	}
	var activeWinidow time.Duration
	if tokenType == commonToken.EmailVerificationTokenType {
		activeWinidow = VerificationTokenExpiry
	} else {
		activeWinidow = PasswordResetTokenExpiry
	}
	verificationTokentExpiryDate := service.timeProvider.Now().Add(activeWinidow)
	emailVerificationToken := &model.Token{
		UserID:    userID,
		TokenHash: string(tokenHash),
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
		logger.Error(err, "Error removing old token")
		return &Error{Message: "Could not remove old token"}
	}
	return nil
}

// RemoveUnusedTokens removes the user old tokens from the database
func (service *TokenService) RemoveUnusedTokens(
	ctx context.Context,
	userID string,
	tokenType commonToken.Type,
) error {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return err
	}
	userIDObject, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		logger.Error(err, "Error converting user id to object id")
		return &Error{Message: InvalidUserIDError}
	}
	err = service.tokenRepository.RemoveAllByUserIDAndTokenType(ctx, userIDObject, tokenType)
	if err != nil {
		logger.Error(err, "Error removing old tokens")
		return &Error{Message: "Could not remove old tokens"}
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
	claims *commonJWT.TokenClaims,
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
	includeFirebaseToken bool,
) (*model.AuthTokensResponse, error) {
	// Auth token creation
	authenticationTokenExpiration := service.timeProvider.Now().Add(AuthenticationTokenDuration)
	authTokenClaims := &commonJWT.TokenClaims{
		Email:  userEmail,
		UserID: userID,
		Type:   commonToken.AuthTokenType,
		Expiry: authenticationTokenExpiration,
	}
	authTokenString, err := service.GenerateJWTToken(ctx, authTokenClaims)
	if err != nil {
		return nil, fmt.Errorf("Error creating authentication token: %v", err)
	}

	// Refresh token creation
	refreshTokenExpiration := service.timeProvider.Now().Add(RefreshTokenDuration)
	refreshTokenClaims := &commonJWT.TokenClaims{
		Email:  userEmail,
		UserID: userID,
		Type:   commonToken.RefreshTokenType,
		Expiry: refreshTokenExpiration,
	}
	refreshTokenString, err := service.GenerateJWTToken(ctx, refreshTokenClaims)
	if err != nil {
		return nil, fmt.Errorf("Error creating refresh token: %v", err)
	}

	response := &model.AuthTokensResponse{
		AuthToken:          *authTokenString,
		AuthTokenExpiry:    authenticationTokenExpiration,
		RefreshToken:       *refreshTokenString,
		RefreshTokenExpiry: refreshTokenExpiration,
		UserEmail:          userEmail,
		UserID:             userID,
	}

	// Generate Firebase custom token if requested
	if includeFirebaseToken {
		firebaseToken, err := service.firebaseService.CreateCustomToken(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("Error creating Firebase custom token: %v", err)
		}
		response.FirebaseToken = firebaseToken
	}

	return response, nil
}

// VerifyJWTToken refreshes an authentication token using a refresh token
func (service *TokenService) VerifyJWTToken(
	ctx context.Context,
	tokenValue string,
) (*commonJWT.TokenClaims, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	// Verify the refresh token
	token, err := service.jwtManager.VerifyToken(tokenValue)
	if err != nil {
		logger.Error(err, "Error verifying token")
		return nil, &Error{
			Message: "Invalid or expired token",
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

// TODO: take out token type check to the caller function

// VerifyTokenValidity verifies a email verification or password reset token validity
func (service *TokenService) VerifyTokenValidity(
	ctx context.Context,
	userID,
	tokenValue string,
	tokenType commonToken.Type,
) (*model.Token, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	userIDObject, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		logger.Error(err, "Error converting user id to object id")
		return nil, &Error{Message: InvalidUserIDError}
	}
	token, err := service.tokenRepository.GetByUserIDAndTokenType(
		ctx,
		userIDObject,
		tokenType,
	)
	if err != nil {
		logger.Error(err, "Error getting token by user id and type")
		return nil, &Error{Message: InvalidTokenError}
	}
	resultError := bcrypt.CompareHashAndPassword([]byte(token.TokenHash), []byte(tokenValue))
	if resultError != nil {
		logger.Error(err, "Invalid verification token")
		return nil, &Error{Message: InvalidTokenError}
	}
	current := service.timeProvider.Now()
	timeDifference := current.Sub(token.ExpiresAt)
	if timeDifference >= 0 {
		return nil, &Error{Message: TokenExpiredError}
	}
	return token, nil
}

// VerifyResetPasswordToken verifies a password reset token validity
func (service *TokenService) VerifyResetPasswordToken(
	ctx context.Context,
	userID,
	tokenValue string,
) (*model.Token, error) {
	token, err := service.VerifyTokenValidity(ctx, userID, tokenValue, commonToken.ResetPasswordTokenType)
	if err != nil {
		return nil, err
	}
	return token, nil
}

// VerifyEmailVerificationToken verifies an email verification token validity
func (service *TokenService) VerifyEmailVerificationToken(
	ctx context.Context,
	userID,
	tokenValue string,
) (*model.Token, error) {
	token, err := service.VerifyTokenValidity(
		ctx,
		userID,
		tokenValue,
		commonToken.EmailVerificationTokenType,
	)
	if err != nil {
		return nil, err
	}
	return token, nil
}

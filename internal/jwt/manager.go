package jwt

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt"
	commonJWT "github.com/quadev-ltd/qd-common/pkg/jwt"
)

// Managerer is an interface for JWTAuthenticator
type Managerer interface {
	GetPublicKey(ctx context.Context) (string, error)
	SignToken(tokenClaims *commonJWT.TokenClaims) (*string, error)
	VerifyToken(token string) (*jwt.Token, error)
	GetClaimsFromToken(token *jwt.Token) (*commonJWT.TokenClaims, error)
}

// Manager is responsible for generating and verifying JWT tokens
type Manager struct {
	keyManager     commonJWT.KeyManagerer
	tokenInspector commonJWT.TokenInspectorer
	tokenVerifier  commonJWT.TokenVerifierer
	tokenSigner    commonJWT.TokenSignerer
}

var _ Managerer = &Manager{}

// NewManager creates a new JWT signer
func NewManager(fileLocation string) (Managerer, error) {
	keyManager, err := commonJWT.NewKeyManager(fileLocation)
	if err != nil {
		return nil, fmt.Errorf("Error creating key manager: %v", err)
	}
	tokenInspector := &commonJWT.TokenInspector{}
	publicKey, err := keyManager.GetPublicKey(context.Background())
	if err != nil {
		return nil, fmt.Errorf("Error getting public key: %v", err)
	}
	tokenVerifier, err := commonJWT.NewTokenVerifier(publicKey)
	if err != nil {
		return nil, fmt.Errorf("Error creating token verifier: %v", err)
	}
	tokenSigner := commonJWT.NewTokenSigner(keyManager.GetRSAPrivateKey())

	return &Manager{
		keyManager,
		tokenInspector,
		tokenVerifier,
		tokenSigner,
	}, nil
}

// GetPublicKey gets the public key
func (authenticator *Manager) GetPublicKey(ctx context.Context) (string, error) {
	return authenticator.keyManager.GetPublicKey(ctx)
}

// SignToken signs a JWT token
func (authenticator *Manager) SignToken(tokenClaims *commonJWT.TokenClaims) (*string, error) {
	claims := []commonJWT.ClaimPair{
		{Key: commonJWT.EmailClaim, Value: tokenClaims.Email},
		{Key: commonJWT.TypeClaim, Value: tokenClaims.Type},
		{Key: commonJWT.ExpiryClaim, Value: tokenClaims.Expiry},
		{Key: commonJWT.UserIDClaim, Value: tokenClaims.UserID},
		{Key: commonJWT.HasPaidFeaturesClaim, Value: tokenClaims.HasPaidFeatures},
	}
	return authenticator.tokenSigner.SignToken(claims...)
}

// VerifyToken verifies a JWT token
func (authenticator *Manager) VerifyToken(tokenString string) (*jwt.Token, error) {
	return authenticator.tokenVerifier.Verify(tokenString)
}

// GetClaimsFromToken gets the email from a JWT token
func (authenticator *Manager) GetClaimsFromToken(token *jwt.Token) (*commonJWT.TokenClaims, error) {
	return authenticator.tokenInspector.GetClaimsFromToken(token)
}

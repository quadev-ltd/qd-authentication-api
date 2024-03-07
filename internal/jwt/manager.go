package jwt

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	commonJWT "github.com/quadev-ltd/qd-common/pkg/jwt"
)

type TokenClaims struct {
	Email  string
	Type   string
	Expiry time.Time
}

// Managerer is an interface for JWTAuthenticator
type Managerer interface {
	GetPublicKey(ctx context.Context) (string, error)
	SignToken(email string, expiry time.Time, tokenType commonJWT.TokenType) (*string, error)
	VerifyToken(token string) (*jwt.Token, error)
	GetClaimsFromToken(token *jwt.Token) (*TokenClaims, error)
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
func (authenticator *Manager) SignToken(email string, expiry time.Time, tokenType commonJWT.TokenType) (*string, error) {
	return authenticator.tokenSigner.SignToken(email, expiry, tokenType)
}

// VerifyToken verifies a JWT token
func (authenticator *Manager) VerifyToken(tokenString string) (*jwt.Token, error) {
	return authenticator.tokenVerifier.Verify(tokenString)
}

// GetClaimsFromToken gets the email from a JWT token
func (authenticator *Manager) GetClaimsFromToken(token *jwt.Token) (*TokenClaims, error) {
	email, err := authenticator.tokenInspector.GetEmailFromToken(token)
	if err != nil {
		return nil, fmt.Errorf("Error getting email from token: %v", err)
	}
	tokenType, err := authenticator.tokenInspector.GetTypeFromToken(token)
	if err != nil {
		return nil, fmt.Errorf("Error getting type claim from token: %v", err)
	}
	expiry, err := authenticator.tokenInspector.GetExpiryFromToken(token)
	if err != nil {
		return nil, fmt.Errorf("Error getting expiry claim from token: %v", err)
	}
	return &TokenClaims{
		Email:  *email,
		Type:   *tokenType,
		Expiry: *expiry,
	}, nil
}

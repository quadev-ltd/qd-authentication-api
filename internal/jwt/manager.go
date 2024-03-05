package jwt

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	commonJWT "github.com/quadev-ltd/qd-common/pkg/jwt"
)

// Managerer is an interface for JWTAuthenticator
type Managerer interface {
	GetPublicKey(ctx context.Context) (string, error)
	SignToken(email string, expiry time.Time, tokenType commonJWT.TokenType) (*string, error)
	VerifyToken(token string) (*jwt.Token, error)
	GetEmailFromToken(token *jwt.Token) (*string, error)
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

// GetEmailFromToken gets the email from a JWT token
func (authenticator *Manager) GetEmailFromToken(token *jwt.Token) (*string, error) {
	return authenticator.tokenInspector.GetEmailFromToken(token)
}

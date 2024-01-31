package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
)

// Signerer is an interface for JWTAuthenticator
type Signerer interface {
	GenerateNewKeyPair() error
	GetPublicKey(ctx context.Context) (string, error)
	SignToken(email string, expiry time.Time) (*string, error)
	VerifyToken(token string) (*jwt.Token, error)
	GetEmailFromToken(token *jwt.Token) (*string, error)
	GetExpiryFromToken(token *jwt.Token) (*time.Time, error)
}

// JWTSigner is responsible for generating and verifying JWT tokens
type JWTSigner struct {
	fileLocation string
	privateKey   *rsa.PrivateKey
	publicKey    *rsa.PublicKey
}

var _ Signerer = &JWTSigner{}

// Key constants
const (
	EmailClaim         = "email"
	ExpiryClaim        = "expiry"
	PublicKeyFileName  = "public.pem"
	PrivateKeyFileName = "private.pem"
	PublicKeyType      = "RSA PUBLIC KEY"
	PrivateKeyType     = "RSA PRIVATE KEY"
)

func createKeysFolderIfNotExists(fileLocation string) error {
	if _, err := os.Stat(fileLocation); os.IsNotExist(err) {
		err := os.Mkdir(fileLocation, 0700)
		if err != nil {
			return err
		}
	}
	return nil
}

func generateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	publicKey := &privateKey.PublicKey

	return privateKey, publicKey, nil
}

func generateKeyFiles(fileLocation string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	createKeysFolderIfNotExists(fileLocation)
	privateKey, publicKey, err := generateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	err = savePrivateKeyToFile(
		privateKey,
		fmt.Sprintf("%s/%s", fileLocation, PrivateKeyFileName),
	)
	if err != nil {
		return nil, nil, err
	}
	err = savePublicKeyToFile(
		publicKey,
		fmt.Sprintf("%s/%s", fileLocation, PublicKeyFileName),
	)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

func savePrivateKeyToFile(privateKey *rsa.PrivateKey, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PrivateKeyType,
		Bytes: privateKeyBytes,
	})

	_, err = file.Write(privateKeyPEM)
	return err
}

func savePublicKeyToFile(publicKey *rsa.PublicKey, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PublicKeyType,
		Bytes: publicKeyBytes,
	})

	_, err = file.Write(publicKeyPEM)
	return err
}

func loadPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	privateKeyPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privateKeyPEM)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func loadPublicKeyFromFile(filename string) (*rsa.PublicKey, error) {
	publicKeyPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(publicKeyPEM)
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return publicKey.(*rsa.PublicKey), nil
}

// NewJWTSigner creates a new JWT signer
func NewJWTSigner(fileLocation string) (Signerer, error) {
	privateKey, err := loadPrivateKeyFromFile(
		fmt.Sprintf("%s/%s", fileLocation, PrivateKeyFileName),
	)
	if err != nil && os.IsNotExist(err) {
		privateKey, publicKey, err := generateKeyFiles(fileLocation)
		if err != nil {
			return nil, err
		}
		return &JWTSigner{
			privateKey:   privateKey,
			publicKey:    publicKey,
			fileLocation: fileLocation,
		}, nil
	} else if err != nil {
		return nil, err
	}
	publicKey, err := loadPublicKeyFromFile(
		fmt.Sprintf("%s/%s", fileLocation, PublicKeyFileName),
	)
	if err != nil {
		return nil, err
	}
	return &JWTSigner{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

// GenerateNewKeyPair generates a new key pair
func (authenticator *JWTSigner) GenerateNewKeyPair() error {
	privateKey, publicKey, err := generateKeyFiles(authenticator.fileLocation)
	if err != nil {
		return err
	}
	authenticator.privateKey = privateKey
	authenticator.publicKey = publicKey
	return nil
}

// GetPublicKey gets the public key
func (authenticator *JWTSigner) GetPublicKey(ctx context.Context) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(authenticator.publicKey)
	if err != nil {
		return "", fmt.Errorf("Failed to marshal public key: %v", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PublicKeyType,
		Bytes: publicKeyBytes,
	})
	return string(publicKeyPEM), nil
}

// SignToken signs a JWT token
func (authenticator *JWTSigner) SignToken(email string, expiry time.Time) (*string, error) {
	tokenClaims := jwt.MapClaims{
		EmailClaim:  email,
		ExpiryClaim: expiry.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)
	tokenString, err := token.SignedString(authenticator.privateKey)
	if err != nil {
		return nil, err
	}
	return &tokenString, nil
}

// VerifyToken verifies a JWT token
func (authenticator *JWTSigner) VerifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return authenticator.publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, &Error{
			Message: "JWT Token is not valid",
		}
	}
	expiry, err := authenticator.GetExpiryFromToken(token)
	if err != nil {
		return nil, err
	}
	if expiry.Before(time.Now()) {
		return nil, &Error{
			Message: "JWT Token is expired",
		}
	}
	return token, nil
}

// GetExpiryFromToken gets the expiry from a JWT token
func (authenticator *JWTSigner) GetExpiryFromToken(token *jwt.Token) (*time.Time, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("JWT Token claims are not valid")
	}
	expiry, ok := claims[ExpiryClaim].(float64)
	if !ok {
		return nil, errors.New("JWT Token expiry is not valid")
	}
	expiryTime := time.Unix(int64(expiry), 0)
	return &expiryTime, nil
}

// GetEmailFromToken gets the email from a JWT token
func (authenticator *JWTSigner) GetEmailFromToken(token *jwt.Token) (*string, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("JWT Token claims are not valid")
	}
	email, ok := claims[EmailClaim].(string)
	if !ok {
		return nil, errors.New("JWT Token email is not valid")
	}
	return &email, nil
}

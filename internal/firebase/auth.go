package firebase

import (
	"context"
	"fmt"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"google.golang.org/api/option"
)

// AuthServicer defines the operations available from Firebase authentication service
type AuthServicer interface {
	VerifyIDToken(ctx context.Context, idToken string) (*auth.Token, error)
	CreateCustomToken(ctx context.Context, uid string) (string, error)
}

// AuthService implements FirebaseAuther using a Firebase auth client
type AuthService struct {
	client *auth.Client
}

// NewAuthService creates a new FirebaseService
func NewAuthService(firebaseConfigPath string) (*AuthService, error) {
	client, err := setupAuthClient(firebaseConfigPath)
	if err != nil {
		return nil, err
	}
	return &AuthService{client: client}, nil
}

// VerifyIDToken verifies the ID token using Firebase's client
func (FirebaseService *AuthService) VerifyIDToken(ctx context.Context, idToken string) (*auth.Token, error) {
	return FirebaseService.client.VerifyIDToken(ctx, idToken)
}

// CreateCustomToken creates a custom token for the given user ID
func (FirebaseService *AuthService) CreateCustomToken(ctx context.Context, uid string) (string, error) {
	return FirebaseService.client.CustomToken(ctx, uid)
}

func setupAuthClient(firebaseConfigPath string) (*auth.Client, error) {
	ctx := context.Background()
	opt := option.WithCredentialsFile(firebaseConfigPath)
	app, err := firebase.NewApp(ctx, nil, opt)
	if err != nil {
		return nil, fmt.Errorf("error initializing firebase app: %v", err)
	}

	authClient, err := app.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting firebase auth client: %v", err)
	}

	return authClient, nil
}

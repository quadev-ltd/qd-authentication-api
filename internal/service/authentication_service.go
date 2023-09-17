package service

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"qd_authentication_api/internal/model"
	"qd_authentication_api/internal/repository"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

// Define the JWT signing key and refresh token expiry
var jwtSigningKey = []byte("your-secret-key")
var refreshTokenExpiry = 7 * 24 * time.Hour // Refresh token expiry set to 7 days

type AuthenticationServicer interface {
	Register(email, password, firstName, lastName string, dateOfBirth *time.Time) (*string, error)
	Verify(verificationToken string) error
	Authenticate(email, password string) (*model.AuthTokensResponse, error)
}

type AuthenticationService struct {
	emailService EmailServicer
	userRepo     repository.UserRepository
}

var _ AuthenticationServicer = &AuthenticationService{}

func generateSalt(length int) (string, error) {
	salt := make([]byte, length)
	_, error := rand.Read(salt)
	if error != nil {
		return "", error
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

func generateVerificationToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	token := base64.URLEncoding.EncodeToString(b)
	return token, nil
}

func NewAuthenticationService(emailService EmailServicer, userRepo repository.UserRepository) *AuthenticationService {
	return &AuthenticationService{userRepo: userRepo, emailService: emailService}
}

func (service *AuthenticationService) Register(email, password, firstName, lastName string, dateOfBirth *time.Time) (*string, error) {
	existingUser, error := service.userRepo.GetByEmail(email)
	if error != nil {
		return nil, error
	}
	if existingUser != nil {
		return nil, &model.EmailInUseError{Email: email}
	}

	// Generate salt
	saltLength := 32
	salt, error := generateSalt(saltLength)
	if error != nil {
		return nil, error
	}

	// Hash password
	hashedPassword, error := bcrypt.GenerateFromPassword([]byte(password+salt), bcrypt.DefaultCost)
	if error != nil {
		return nil, error
	}

	verificationToken, error := generateVerificationToken()
	if error != nil {
		return nil, error
	}

	user := &model.User{
		Email:             email,
		VerificationToken: verificationToken,
		PasswordHash:      string(hashedPassword),
		PasswordSalt:      salt,
		FirstName:         firstName,
		LastName:          lastName,
		DateOfBirth:       *dateOfBirth,
		RegistrationDate:  time.Now(),
		AccountStatus:     model.AccountStatusUnverified,
	}

	// Validate the user object
	if error := model.ValidateUser(user); error != nil {
		return nil, error
	}

	// Create the user in the repository
	if error := service.userRepo.Create(user); error != nil {
		return nil, error
	}

	if error := service.emailService.SendVerificationMail(user.Email, user.FirstName, user.VerificationToken); error != nil {
		return nil, error
	}

	return &verificationToken, nil
}

func (service *AuthenticationService) Verify(verificationToken string) error {
	user, error := service.userRepo.GetByVerificationToken(verificationToken)
	if error != nil {
		return error
	}
	if user == nil {
		return fmt.Errorf("Invalid verification token")
	}

	user.AccountStatus = model.AccountStatusVerified

	if error := service.userRepo.Update(user); error != nil {
		return error
	}

	return nil
}

func (service *AuthenticationService) Authenticate(email, password string) (*model.AuthTokensResponse, error) {
	user, resultError := service.userRepo.GetByEmail(email)
	if resultError != nil {
		return nil, resultError
	}

	if user == nil {
		return nil, &model.WrongEmailOrPassword{FieldName: "Email"}
	}

	resultError = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password+user.PasswordSalt))
	if resultError != nil {
		return nil, &model.WrongEmailOrPassword{FieldName: "Password"}
	}

	// Set the expiration time for the authentication token
	authTokenExpiration := time.Now().Add(15 * time.Minute) // Adjust the expiration time as needed

	// Generate the JWT claims for the authentication token
	authTokenClaims := jwt.MapClaims{
		"email": user.Email,
		// Add any other relevant claims (e.g., user ID, role, etc.)
		"exp": authTokenExpiration.Unix(),
	}

	// Create the authentication token
	authToken := jwt.NewWithClaims(jwt.SigningMethodHS256, authTokenClaims)
	authTokenString, err := authToken.SignedString(jwtSigningKey)
	if err != nil {
		return nil, err
	}

	// Set the expiration time for the refresh token
	refreshTokenExpiration := time.Now().Add(refreshTokenExpiry)

	// Generate the JWT claims for the refresh token
	refreshTokenClaims := jwt.MapClaims{
		"email": user.Email,
		// Add any other relevant claims
		"exp": refreshTokenExpiration.Unix(),
	}

	// Create the refresh token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
	refreshTokenString, err := refreshToken.SignedString(jwtSigningKey)
	if err != nil {
		return nil, err
	}

	// Build the response containing the authentication token, refresh token, and other information
	response := &model.AuthTokensResponse{
		AuthToken:          authTokenString,
		AuthTokenExpiry:    authTokenExpiration,
		RefreshToken:       refreshTokenString,
		RefreshTokenExpiry: refreshTokenExpiration,
		UserEmail:          user.Email,
		// Add any other relevant user information
	}

	return response, nil
}

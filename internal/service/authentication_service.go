package service

import (
	"crypto/rand"
	"encoding/base64"
	"qd_authentication_api/internal/model"
	"qd_authentication_api/internal/repository"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

// TODO: Analyse best expiry times for tokens
const AuthenticationTokenExpiry = 2 * time.Hour // Authentication token expiry set to 2 hours
const RefreshTokenExpiry = 7 * 24 * time.Hour   // Refresh token expiry set to 7 days
const VerificationTokenExpiry = 24 * time.Hour  // Verification token expiry set to 24 hours

type AuthenticationServicer interface {
	Register(email, password, firstName, lastName string, dateOfBirth *time.Time) error
	VerifyEmail(verificationToken string) error
	Authenticate(email, password string) (*model.AuthTokensResponse, error)
}

type AuthenticationService struct {
	emailService EmailServicer
	userRepo     repository.UserRepository
	key          []byte
}

var _ AuthenticationServicer = &AuthenticationService{}

type ServiceError struct {
	Message string
}

func (e *ServiceError) Error() string {
	return e.Message
}

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

func NewAuthenticationService(
	emailService EmailServicer,
	userRepo repository.UserRepository,
	key string,
) *AuthenticationService {
	return &AuthenticationService{
		userRepo:     userRepo,
		emailService: emailService,
		key:          []byte(key),
	}
}

func generateHash(password string) ([]byte, *string, error) {
	// Generate salt
	saltLength := 32
	salt, error := generateSalt(saltLength)
	if error != nil {
		return nil, nil, error
	}

	// Hash password
	hashedPassword, error := bcrypt.GenerateFromPassword([]byte(password+salt), bcrypt.DefaultCost)
	if error != nil {
		return nil, nil, error
	}

	return hashedPassword, &salt, nil
}

func (service *AuthenticationService) Register(email, password, firstName, lastName string, dateOfBirth *time.Time) error {
	existingUser, error := service.userRepo.GetByEmail(email)
	if error != nil {
		return error
	}
	if existingUser != nil {
		return &model.EmailInUseError{Email: email}
	}

	hashedPassword, salt, error := generateHash(password)
	if error != nil {
		return error
	}

	verificationToken, error := generateVerificationToken()
	if error != nil {
		return error
	}

	verificationTokentExpiryDate := time.Now().Add(VerificationTokenExpiry)

	user := &model.User{
		Email:                       email,
		VerificationToken:           verificationToken,
		VerificationTokenExpiryDate: verificationTokentExpiryDate,
		PasswordHash:                string(hashedPassword),
		PasswordSalt:                *salt,
		FirstName:                   firstName,
		LastName:                    lastName,
		DateOfBirth:                 *dateOfBirth,
		RegistrationDate:            time.Now(),
		AccountStatus:               model.AccountStatusUnverified,
	}

	// Validate the user object
	if error := model.ValidateUser(user); error != nil {
		return error
	}

	// Create the user in the repository
	if error := service.userRepo.Create(user); error != nil {
		return error
	}

	if error := service.emailService.SendVerificationMail(user.Email, user.FirstName, user.VerificationToken); error != nil {
		return error
	}

	return nil
}

func (service *AuthenticationService) VerifyEmail(verificationToken string) error {
	user, error := service.userRepo.GetByVerificationToken(verificationToken)
	if error != nil {
		return error
	}
	if user.AccountStatus == model.AccountStatusVerified {
		return &ServiceError{Message: "Email already verified"}
	}
	if user == nil {
		return &ServiceError{Message: "Invalid verification token"}
	}
	current := time.Now()
	timeDifference := current.Sub(user.VerificationTokenExpiryDate)
	if timeDifference >= VerificationTokenExpiry {
		return &ServiceError{Message: "Verification token expired"}
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

	authenticationTokenExpiryDate := time.Now().Add(AuthenticationTokenExpiry)

	// Generate the JWT claims for the authentication token
	authTokenClaims := jwt.MapClaims{
		"email": user.Email,
		// Add any other relevant claims (e.g., user ID, role, etc.)
		"exp": authenticationTokenExpiryDate.Unix(),
	}

	// Create the authentication token
	authToken := jwt.NewWithClaims(jwt.SigningMethodHS256, authTokenClaims)
	authTokenString, err := authToken.SignedString(service.key)
	if err != nil {
		return nil, err
	}

	// Set the expiration time for the refresh token
	refreshTokenExpiration := time.Now().Add(RefreshTokenExpiry)

	// Generate the JWT claims for the refresh token
	refreshTokenClaims := jwt.MapClaims{
		"email": user.Email,
		// Add any other relevant claims
		"exp": refreshTokenExpiration.Unix(),
	}

	// Create the refresh token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
	refreshTokenString, err := refreshToken.SignedString(service.key)
	if err != nil {
		return nil, err
	}

	// Build the response containing the authentication token, refresh token, and other information
	response := &model.AuthTokensResponse{
		AuthToken:          authTokenString,
		AuthTokenExpiry:    authenticationTokenExpiryDate,
		RefreshToken:       refreshTokenString,
		RefreshTokenExpiry: refreshTokenExpiration,
		UserEmail:          user.Email,
		// Add any other relevant user information
	}

	return response, nil
}

package service

import (
	"qd_authentication_api/internal/model"
	"qd_authentication_api/internal/repository"
	"time"

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
	VerifyTokenAndDecodeEmail(token string) (*string, error)
	ResendEmailVerification(email string) error
}

type AuthenticationService struct {
	emailService     EmailServicer
	userRepository   repository.UserRepositoryer
	jwtAuthenticator JWTAthenticatorer
}

var _ AuthenticationServicer = &AuthenticationService{}

func NewAuthenticationService(
	emailService EmailServicer,
	userRepository repository.UserRepositoryer,
	jwtAuthenticator JWTAthenticatorer,
) AuthenticationServicer {
	return &AuthenticationService{
		userRepository:   userRepository,
		emailService:     emailService,
		jwtAuthenticator: jwtAuthenticator,
	}
}

func (service *AuthenticationService) Register(email, password, firstName, lastName string, dateOfBirth *time.Time) error {
	existingUser, error := service.userRepository.GetByEmail(email)
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
	if error := service.userRepository.Create(user); error != nil {
		return error
	}

	if error := service.emailService.SendVerificationMail(user.Email, user.FirstName, user.VerificationToken); error != nil {
		return error
	}

	return nil
}

func (service *AuthenticationService) VerifyEmail(verificationToken string) error {
	user, error := service.userRepository.GetByVerificationToken(verificationToken)
	if error != nil {
		return error
	}
	if user == nil {
		return &ServiceError{Message: "Invalid verification token"}
	}
	if user.AccountStatus == model.AccountStatusVerified {
		return &ServiceError{Message: "Email already verified"}
	}
	current := time.Now()
	timeDifference := current.Sub(user.VerificationTokenExpiryDate)
	if timeDifference >= VerificationTokenExpiry {
		return &ServiceError{Message: "Verification token expired"}
	}
	user.AccountStatus = model.AccountStatusVerified

	if error := service.userRepository.Update(user); error != nil {
		return error
	}

	return nil
}

func (service *AuthenticationService) Authenticate(email, password string) (*model.AuthTokensResponse, error) {
	user, resultError := service.userRepository.GetByEmail(email)
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
	authTokenString, err := service.jwtAuthenticator.SignToken(user.Email, authenticationTokenExpiryDate)
	if err != nil {
		return nil, &ServiceError{
			Message: "Error creating authentication token.",
		}
	}

	refreshTokenExpiration := time.Now().Add(RefreshTokenExpiry)
	refreshTokenString, err := service.jwtAuthenticator.SignToken(user.Email, refreshTokenExpiration)
	if err != nil {
		return nil, &ServiceError{
			Message: "Error creating refresh token.",
		}
	}

	response := &model.AuthTokensResponse{
		AuthToken:          *authTokenString,
		AuthTokenExpiry:    authenticationTokenExpiryDate,
		RefreshToken:       *refreshTokenString,
		RefreshTokenExpiry: refreshTokenExpiration,
		UserEmail:          user.Email,
	}

	return response, nil
}

func (service *AuthenticationService) VerifyTokenAndDecodeEmail(token string) (*string, error) {
	jwtToken, error := service.jwtAuthenticator.VerifyToken(token)
	if error != nil {
		return nil, error
	}
	email, error := service.jwtAuthenticator.GetEmailFromToken(jwtToken)
	if error != nil {
		return nil, error
	}
	return email, nil
}

func (service *AuthenticationService) ResendEmailVerification(email string) error {
	user, error := service.userRepository.GetByEmail(email)
	if error != nil {
		return error
	}
	if user == nil {
		return &ServiceError{Message: "Invalid email"}
	}
	if user.AccountStatus == model.AccountStatusVerified {
		return &ServiceError{Message: "Email already verified"}
	}

	verificationToken, error := generateVerificationToken()
	if error != nil {
		return error
	}
	user.VerificationToken = verificationToken
	user.VerificationTokenExpiryDate = time.Now().Add(VerificationTokenExpiry)

	if error := service.userRepository.Update(user); error != nil {
		return error
	}

	if error := service.emailService.SendVerificationMail(user.Email, user.FirstName, user.VerificationToken); error != nil {
		return error
	}

	return nil
}

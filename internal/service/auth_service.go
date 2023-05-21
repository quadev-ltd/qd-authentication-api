package service

import (
	"crypto/rand"
	"encoding/base64"
	"qd_authentication_api/internal/model"
	"qd_authentication_api/internal/repository"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type AuthServicer interface {
	Register(email, password, firstName, lastName string, dateOfBirth *time.Time) error
}

type AuthService struct {
	emailService EmailServicer
	userRepo     repository.UserRepository
}

var _ AuthServicer = &AuthService{}

func NewAuthService(emailService EmailServicer, userRepo repository.UserRepository) *AuthService {
	return &AuthService{userRepo: userRepo, emailService: emailService}
}

func (service *AuthService) Register(email, password, firstName, lastName string, dateOfBirth *time.Time) error {
	existingUser, error := service.userRepo.GetByEmail(email)
	if error != nil {
		return error
	}
	if existingUser != nil {
		return &model.EmailInUseError{Email: email}
	}

	// Generate salt
	saltLength := 32
	salt, error := generateSalt(saltLength)
	if error != nil {
		return error
	}

	// Hash password
	hashedPassword, error := bcrypt.GenerateFromPassword([]byte(password+salt), bcrypt.DefaultCost)
	if error != nil {
		return error
	}

	verificationToken, error := generateVerificationToken()
	if error != nil {
		return error
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

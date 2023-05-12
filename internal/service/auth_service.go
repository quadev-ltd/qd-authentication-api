package service

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"qd_authentication_api/internal/model"
	"qd_authentication_api/internal/repository"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const SecretKey = "your-secret-key"

type AuthService struct {
	userRepo repository.UserRepository
}

func NewAuthService(userRepo repository.UserRepository) *AuthService {
	return &AuthService{userRepo: userRepo}
}

func (s *AuthService) Register(email, password, firstName, lastName string, dateOfBirth *time.Time) error {
	existingUser, error := s.userRepo.GetByEmail(email)
	if error != nil {
		return error
	}
	if existingUser != nil {
		return fmt.Errorf("email is already in use")
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

	user := &model.User{
		ID:               uuid.New(),
		Email:            email,
		PasswordHash:     string(hashedPassword),
		PasswordSalt:     salt,
		FirstName:        firstName,
		LastName:         lastName,
		DateOfBirth:      *dateOfBirth,
		RegistrationDate: time.Now(),
		AccountStatus:    model.AccountStatusActive,
	}

	// Validate the user object
	if error := model.ValidateUser(user); error != nil {
		return error
	}

	// Create the user in the repository
	if error := s.userRepo.Create(user); error != nil {
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

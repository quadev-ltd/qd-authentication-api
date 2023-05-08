package repository

import (
	"qd_authentication_api/internal/model"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMockUserRepository_Create(test *testing.T) {
	mockRepo := &MockUserRepository{}
	user := &model.User{
		ID:               uuid.NewString(),
		Email:            "mockuser@example.com",
		Username:         "mockuser",
		PasswordHash:     "hashedpassword",
		PasswordSalt:     "saltpassword",
		FirstName:        "Mock",
		LastName:         "User",
		DateOfBirth:      time.Date(1990, time.January, 1, 0, 0, 0, 0, time.UTC),
		RegistrationDate: time.Now(),
		LastLoginDate:    time.Now(),
		AccountStatus:    model.AccountStatusActive,
	}

	err := mockRepo.Create(user)
	if err != nil {
		test.Errorf("unexpected error: %v", err)
	}

	createdUser, err := mockRepo.GetByEmail(user.Email)
	if err != nil {
		test.Errorf("unexpected error: %v", err)
	}

	if createdUser == nil {
		test.Error("user not found")
	} else {
		if createdUser.Email != user.Email {
			test.Errorf("expected email %v, got %v", user.Email, createdUser.Email)
		}
		if createdUser.PasswordHash != user.PasswordHash {
			test.Errorf("expected password %v, got %v", user.PasswordHash, createdUser.PasswordHash)
		}
	}
}

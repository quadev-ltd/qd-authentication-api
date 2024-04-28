package service

import (
	"context"
	_ "embed"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

//go:embed templates/verification_email_test.txt
var verificationEmailTest string

//go:embed templates/reset_password_email_test.txt
var passwordResetEmailTest string

//go:embed templates/verification_success_email_test.txt
var verificationSuccessEmailTest string

func TestCreateVerificationEmailContent(test *testing.T) {
	emailService := &EmailService{
		config: EmailServiceConfig{
			AppName:                   "MyApp",
			EmailVerificationEndpoint: "http://myapp.com/",
		},
	}

	userName := "Test"
	userID := primitive.NewObjectID().Hex()
	dest := "test@myapp.com"
	token := "abcd1234"

	expectedSubject := "Welcome to MyApp"
	// expectedBody := fmt.Sprintf(" Hi Test,\nYou've just signed up to MyApp!\nWe need to verify your email.\nPlease click on the following link to verify your account:\n<a href=\"http://myapp.com/user/%s/email/abcd1234\">Verify your email</a>\n\nThanks.", userID)
	expectedBody := strings.ReplaceAll(verificationEmailTest, "{userID}", userID)
	subject, body, err := emailService.CreateVerificationEmailContent(context.Background(), dest, userName, userID, token)
	if err != nil {
		test.Fatal(err)
	}

	assert.Equal(test, expectedSubject, subject)
	assert.Equal(test, expectedBody, body)
}

func TestCreatePasswordResetEmailContent(test *testing.T) {
	emailService := &EmailService{
		config: EmailServiceConfig{
			AppName:                   "MyApp",
			EmailVerificationEndpoint: "http://myapp.com/",
		},
	}

	userName := "Test"
	userID := primitive.NewObjectID().Hex()
	dest := "test@myapp.com"
	token := "abcd1234"

	expectedSubject := "Password Reset Request"
	expectedBody := strings.ReplaceAll(passwordResetEmailTest, "{userID}", userID)

	subject, body := emailService.CreatePasswordResetEmailContent(
		context.Background(),
		dest,
		userName,
		userID,
		token,
	)

	assert.Equal(test, expectedSubject, subject)
	assert.Equal(test, expectedBody, body)
}

func TestCreateVerificationSuccessMailContent(test *testing.T) {
	emailService := &EmailService{
		config: EmailServiceConfig{
			AppName:                   "MyApp",
			EmailVerificationEndpoint: "http://myapp.com/",
		},
	}

	userName := "Test"

	expectedSubject := "Email Verification Success"
	expectedBody := verificationSuccessEmailTest

	subject, body := emailService.CreateVerificationSuccessEmailContent(
		context.Background(),
		userName,
	)

	assert.Equal(test, expectedSubject, subject)
	assert.Equal(test, expectedBody, body)
}

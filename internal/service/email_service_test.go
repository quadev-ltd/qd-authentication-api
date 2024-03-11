package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

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
	expectedBody := fmt.Sprintf("Hi Test,\nYou've just signed up to MyApp!\nWe need to verify your email.\nPlease click on the following link to verify your account:\nhttp://myapp.com/user/%s/email/abcd1234\n\nThanks.", userID)

	subject, body := emailService.CreateVerificationEmailContent(context.Background(), dest, userName, userID, token)

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
	expectedBody := fmt.Sprintf(
		"Hi Test,\nYou recently requested to reset your password for your MyApp account. To complete the process, please click the link below:\nhttp://myapp.com/user/%s/password/abcd1234\n\nFor security reasons, this link will expire in soon after generated. If you did not request a password reset, please ignore this email or contact us if you have concerns about unauthorized activity on your account.\n\nIf you're having trouble clicking the password reset link, copy and paste the URL below into your web browser:/nhttp://myapp.com/user/%s/password/abcd1234\n\nThanks.",
		userID,
		userID,
	)

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

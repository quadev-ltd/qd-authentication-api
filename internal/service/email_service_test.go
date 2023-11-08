package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateVerificationEmailContent(test *testing.T) {
	emailService := &EmailService{
		config: EmailServiceConfig{
			AppName:                   "MyApp",
			EmailVerificationEndpoint: "http://myapp.com",
		},
	}

	userName := "Test"
	dest := "test@myapp.com"
	token := "abcd1234"

	expectedSubject := "Welcome to MyApp"
	expectedBody := "Hi Test,\nYou've just signed up to MyApp!\nWe need to verify your email.\nPlease click on the following link to verify your account:\nhttp://myapp.com/verify/abcd1234\n\nThanks."

	subject, body := emailService.CreateVerificationEmailContent(context.Background(), dest, userName, token)

	assert.Equal(test, expectedSubject, subject)
	assert.Equal(test, expectedBody, body)
}

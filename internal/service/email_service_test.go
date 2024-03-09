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

package service

import (
	"context"
	_ "embed"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

//go:embed email_templates/verification_email_test.txt
var verificationEmailTest string

//go:embed email_templates/reset_password_email_test.txt
var passwordResetEmailTest string

//go:embed email_templates/verification_success_email_test.txt
var verificationSuccessEmailTest string

//go:embed email_templates/delete_user_success_email_test.txt
var deleteUserSuccessEmailTest string

//go:embed email_templates/authentication_success_email_test.txt
var authenticationSuccessEmailTest string

func TestCreateVerificationEmailContent(test *testing.T) {
	emailService := &EmailService{
		appName:                   "MyApp",
		emailVerificationEndpoint: "http://myapp.com/",
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
		appName:                   "MyApp",
		emailVerificationEndpoint: "http://myapp.com/",
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

func TestCreateVerificationSuccessEmailContent(test *testing.T) {
	emailService := &EmailService{
		appName:                   "MyApp",
		emailVerificationEndpoint: "http://myapp.com/",
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

func TestCreateAuthenticationSuccessEmailContent(test *testing.T) {
	emailService := &EmailService{
		appName:                   "appName",
		emailVerificationEndpoint: "http://myapp.com/",
	}

	userName := "firstName"

	expectedSubject := "Authentication Success"
	expectedBody := authenticationSuccessEmailTest

	subject, body := emailService.CreateAuthenticationSuccessEmailContent(
		context.Background(),
		userName,
	)

	assert.Equal(test, expectedSubject, subject)
	assert.Equal(test, expectedBody, body)
}

func TestCreateDeleteUserSuccessEmailContent(test *testing.T) {
	emailService := &EmailService{
		appName:                   "appName",
		emailVerificationEndpoint: "http://myapp.com/",
	}

	userName := "firstName"

	expectedSubject := "Your Account Has Been Successfully Deleted"
	expectedBody := deleteUserSuccessEmailTest

	subject, body := emailService.CreateDeletedUserEmailContent(
		context.Background(),
		userName,
	)

	assert.Equal(test, expectedSubject, subject)
	assert.Equal(test, expectedBody, body)
}

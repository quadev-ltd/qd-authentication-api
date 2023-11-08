package service

import (
	"context"
	"fmt"
	"net/smtp"
)

// EmailServiceConfig constains the configuration for the email service
type EmailServiceConfig struct {
	AppName                   string
	EmailVerificationEndpoint string
	From                      string
	Password                  string
	Host                      string
	Port                      string
}

// EmailServicer is the interface for the email service
type EmailServicer interface {
	SendVerificationMail(ctx context.Context, dest string, userName, verificationToken string) error
}

// EmailService is the implementation of the email service
type EmailService struct {
	config EmailServiceConfig
	sender SMTPServicer
}

var _ EmailServicer = &EmailService{}

// NewEmailService creates a new email service
func NewEmailService(config EmailServiceConfig, sender SMTPServicer) *EmailService {

	return &EmailService{
		config: config,
		sender: &SMTPService{},
	}
}

func (service *EmailService) sendMail(dest string, subject string, body string) error {
	message := "From: " + service.config.From + "\n" +
		"To: " + dest + "\n" +
		"Subject: " + subject + "\n\n" +
		body
	config := service.config
	auth := smtp.PlainAuth("", config.From, config.Password, config.Host)
	resultError := smtp.SendMail(
		fmt.Sprintf("%s:%s", config.Host, config.Port),
		auth,
		config.From, []string{dest}, []byte(message))
	return resultError
}

// CreateVerificationEmailContent creates the content of the verification email
func (service *EmailService) CreateVerificationEmailContent(ctx context.Context, destination string, userName, verificationToken string) (string, string) {
	subject := fmt.Sprintf("Welcome to %s", service.config.AppName)
	body := fmt.Sprintf("Hi %s,\nYou've just signed up to %s!\nWe need to verify your email.\nPlease click on the following link to verify your account:\n%s\n\nThanks.", userName, service.config.AppName, service.config.EmailVerificationEndpoint+"/verify/"+verificationToken)
	return subject, body
}

// SendVerificationMail sends a verification email to the given destination
func (service *EmailService) SendVerificationMail(ctx context.Context, destination, userName, verificationToken string) error {
	subject, body := service.CreateVerificationEmailContent(ctx, destination, userName, verificationToken)
	error := service.sendMail(destination, subject, body)
	return error
}

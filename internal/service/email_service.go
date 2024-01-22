package service

import (
	"context"
	"fmt"
	"time"

	pkgLogger "github.com/quadev-ltd/qd-common/pkg/log"
	commonTLS "github.com/quadev-ltd/qd-common/pkg/tls"

	"qd-authentication-api/pb/gen/go/pb_email"
)

// EmailServiceConfig constains the configuration for the email service
type EmailServiceConfig struct {
	AppName                   string
	EmailVerificationEndpoint string
	GRPCHost                  string
	GRPCPort                  string
}

// EmailServicer is the interface for the email service
type EmailServicer interface {
	SendVerificationMail(ctx context.Context, dest string, userName, verificationToken string) error
}

// EmailService is the implementation of the email service
type EmailService struct {
	config EmailServiceConfig
}

var _ EmailServicer = &EmailService{}

// NewEmailService creates a new email service
func NewEmailService(config EmailServiceConfig) *EmailService {

	return &EmailService{
		config: config,
	}
}

func (service *EmailService) sendMail(ctx context.Context, dest string, subject string, body string) error {
	emailServiceGRPCAddress := fmt.Sprintf("%s:%s", service.config.GRPCHost, service.config.GRPCPort)

	conn, err := commonTLS.CreateGRPCConnection(emailServiceGRPCAddress)
	if err != nil {
		return fmt.Errorf("Could not connect to email service: %v", err)
	}
	defer conn.Close()

	emailClient := pb_email.NewEmailServiceClient(conn)

	req := &pb_email.SendEmailRequest{
		To:      dest,
		Subject: subject,
		Body:    body,
	}

	correlationID, error := pkgLogger.GetCorrelationIDFromContext(ctx)
	if error != nil {
		return fmt.Errorf("Error getting correlation ID from context: %v", error)
	}
	newOutgoingCtx := pkgLogger.AddCorrelationIDToContext(ctx, *correlationID)
	clientCtx, cancel := context.WithTimeout(newOutgoingCtx, time.Second*10)
	defer cancel()

	res, err := emailClient.SendEmail(clientCtx, req)
	if err != nil {
		return fmt.Errorf("Error sending email via gRPC: %v", err)
	}

	if !res.GetSuccess() {
		return fmt.Errorf("Failed to send email: %s", res.GetMessage())
	}

	return nil
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
	error := service.sendMail(ctx, destination, subject, body)
	return error
}

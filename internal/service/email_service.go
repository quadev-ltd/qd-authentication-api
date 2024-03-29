package service

import (
	"context"
	"fmt"
	"time"

	commonLogger "github.com/quadev-ltd/qd-common/pkg/log"
	commonTLS "github.com/quadev-ltd/qd-common/pkg/tls"

	"qd-authentication-api/pb/gen/go/pb_email"
)

// EmailServiceConfig constains the configuration for the email service
type EmailServiceConfig struct {
	AppName                   string
	EmailVerificationEndpoint string
	GRPCHost                  string
	GRPCPort                  string
	TLSEnabled                bool
}

// EmailServicer is the interface for the email service
type EmailServicer interface {
	SendVerificationMail(ctx context.Context, dest string, userName, userID, verificationToken string) error
	SendPasswordResetMail(ctx context.Context, dest string, userName, userID, resetToken string) error
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
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return err
	}
	emailServiceGRPCAddress := fmt.Sprintf("%s:%s", service.config.GRPCHost, service.config.GRPCPort)

	conn, err := commonTLS.CreateGRPCConnection(emailServiceGRPCAddress, service.config.TLSEnabled)
	if err != nil {
		logger.Error(err, "Could not connect to email service")
		return fmt.Errorf("Could not connect to email service")
	}
	defer conn.Close()

	emailClient := pb_email.NewEmailServiceClient(conn)

	req := &pb_email.SendEmailRequest{
		To:      dest,
		Subject: subject,
		Body:    body,
	}

	newOutgoingCtx, err := commonLogger.TransferCorrelationIDToOutgoingContext(ctx)
	if err != nil {
		logger.Error(err, "Error getting correlation ID from context")
		return fmt.Errorf("Error getting correlation ID from context")
	}

	clientCtx, cancel := context.WithTimeout(newOutgoingCtx, time.Second*10)
	defer cancel()

	res, err := emailClient.SendEmail(clientCtx, req)
	if err != nil {
		logger.Error(err, "Error sending email data via gRPC")
		return fmt.Errorf("Error sending email data via gRPC")
	}

	if !res.GetSuccess() {
		logger.Error(err, "Failed to send email")
		return fmt.Errorf("Failed to send email")
	}

	return nil
}

// CreateVerificationEmailContent creates the content of the verification email
func (service *EmailService) CreateVerificationEmailContent(
	ctx context.Context,
	destination,
	userName,
	userID,
	verificationToken string,
) (string, string) {
	subject := fmt.Sprintf("Welcome to %s", service.config.AppName)
	emailVerificationLink := fmt.Sprintf("%suser/%s/email/%s", service.config.EmailVerificationEndpoint, userID, verificationToken)
	body := fmt.Sprintf("Hi %s,\nYou've just signed up to %s!\nWe need to verify your email.\nPlease click on the following link to verify your account:\n%s\n\nThanks.", userName, service.config.AppName, emailVerificationLink)
	return subject, body
}

// SendVerificationMail sends a verification email to the given destination
func (service *EmailService) SendVerificationMail(
	ctx context.Context,
	destination,
	userName,
	userID,
	verificationToken string,
) error {
	subject, body := service.CreateVerificationEmailContent(ctx, destination, userName, userID, verificationToken)
	err := service.sendMail(ctx, destination, subject, body)
	return err
}

// CreatePasswordResetEmailContent creates the content of the verification email
func (service *EmailService) CreatePasswordResetEmailContent(ctx context.Context, destination string, userName, userID, verificationToken string) (string, string) {
	subject := "Password Reset Request"
	passwordResetLink := fmt.Sprintf("%suser/%s/password/%s", service.config.EmailVerificationEndpoint, userID, verificationToken)
	body := fmt.Sprintf(
		"Hi %s,\nYou recently requested to reset your password for your %s account. To complete the process, please click the link below:\n%s\n\nFor security reasons, this link will expire in soon after generated. If you did not request a password reset, please ignore this email or contact us if you have concerns about unauthorized activity on your account.\n\nIf you're having trouble clicking the password reset link, copy and paste the URL below into your web browser:/n%s\n\nThanks.",
		userName,
		service.config.AppName,
		passwordResetLink,
		passwordResetLink,
	)
	return subject, body
}

// SendPasswordResetMail sends a verification email to the given destination
func (service *EmailService) SendPasswordResetMail(ctx context.Context, destination, userName, userID, verificationToken string) error {
	subject, body := service.CreatePasswordResetEmailContent(ctx, destination, userName, userID, verificationToken)
	err := service.sendMail(ctx, destination, subject, body)
	return err
}

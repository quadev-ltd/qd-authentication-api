package service

import (
	"context"
	// Embeded files are necessary for email templates
	_ "embed"
	"fmt"
	"strings"
	"time"

	"github.com/quadev-ltd/qd-common/pb/gen/go/pb_email"
	commonLogger "github.com/quadev-ltd/qd-common/pkg/log"
	commonTLS "github.com/quadev-ltd/qd-common/pkg/tls"
)

//go:embed templates/verification_email.txt
var verificationEmail string

//go:embed templates/reset_password.txt
var passwordResetEmail string

//go:embed templates/verification_success_email.txt
var verificationSuccessEmail string

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
	SendEVerificationSuccessMail(ctx context.Context, dest, userName string) error
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
) (string, string, error) {
	subject := fmt.Sprintf("Welcome to %s", service.config.AppName)
	emailVerificationLink := fmt.Sprintf("%s/user/%s/email/%s", service.config.EmailVerificationEndpoint, userID, verificationToken)

	body := strings.ReplaceAll(string(verificationEmail), "{firstName}", userName)
	body = strings.ReplaceAll(body, "{appName}", service.config.AppName)
	body = strings.ReplaceAll(body, "{emailVerificationLink}", emailVerificationLink)
	return subject, body, nil
}

// SendVerificationMail sends a verification email to the given destination
func (service *EmailService) SendVerificationMail(
	ctx context.Context,
	destination,
	userName,
	userID,
	verificationToken string,
) error {
	subject, body, err := service.CreateVerificationEmailContent(ctx, destination, userName, userID, verificationToken)
	if err != nil {
		return err
	}
	err = service.sendMail(ctx, destination, subject, body)
	return err
}

// CreatePasswordResetEmailContent creates the content of the verification email
func (service *EmailService) CreatePasswordResetEmailContent(ctx context.Context, destination string, userName, userID, verificationToken string) (string, string) {
	subject := "Password Reset Request"
	passwordResetLink := fmt.Sprintf("%suser/%s/password/%s", service.config.EmailVerificationEndpoint, userID, verificationToken)

	body := strings.ReplaceAll(passwordResetEmail, "{firstName}", userName)
	body = strings.ReplaceAll(body, "{appName}", service.config.AppName)
	body = strings.ReplaceAll(body, "{resetPasswordLink}", passwordResetLink)

	return subject, body
}

// SendPasswordResetMail sends a verification email to the given destination
func (service *EmailService) SendPasswordResetMail(ctx context.Context, destination, userName, userID, verificationToken string) error {
	subject, body := service.CreatePasswordResetEmailContent(ctx, destination, userName, userID, verificationToken)
	err := service.sendMail(ctx, destination, subject, body)
	return err
}

// CreateVerificationSuccessEmailContent generates teh content for the success notification
func (service *EmailService) CreateVerificationSuccessEmailContent(ctx context.Context, userName string) (string, string) {
	subject := "Email Verification Success"
	body := strings.ReplaceAll(verificationSuccessEmail, "{firstName}", userName)
	return subject, body
}

// SendEVerificationSuccessMail sends an email verification success email
func (service *EmailService) SendEVerificationSuccessMail(ctx context.Context, dest, userName string) error {
	subject, body := service.CreateVerificationSuccessEmailContent(ctx, userName)
	return service.sendMail(ctx, dest, subject, body)
}

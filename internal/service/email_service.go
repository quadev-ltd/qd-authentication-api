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
	"google.golang.org/grpc"
)

//go:embed email_templates/verification_email.txt
var verificationEmail string

//go:embed email_templates/reset_password_email.txt
var passwordResetEmail string

//go:embed email_templates/verification_success_email.txt
var verificationSuccessEmail string

//go:embed email_templates/reset_password_success_email.txt
var passwordResetSuccessEmail string

//go:embed email_templates/delete_user_success_email.txt
var deleteUserSuccessEmail string

//go:embed email_templates/authentication_success_email.txt
var authenticationSuccessEmail string

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
	SendVerificationSuccessEmail(ctx context.Context, dest, userName string) error
	SendVerificationEmail(ctx context.Context, dest string, userName, userID, verificationToken string) error
	SendPasswordResetEmail(ctx context.Context, dest string, userName, userID, resetToken string) error
	SendPasswordResetSuccessEmail(ctx context.Context, dest string, userName string) error
	SendAuthenticationSuccessEmail(ctx context.Context, dest, userName string) error
	SendDeletedUserEmail(ctx context.Context, dest, userName string) error
	Close() error
}

// EmailService is the implementation of the email service
type EmailService struct {
	connection                *grpc.ClientConn
	emailVerificationEndpoint string
	appName                   string
}

var _ EmailServicer = &EmailService{}

// NewEmailService creates a new email service
func NewEmailService(config EmailServiceConfig) (*EmailService, error) {
	emailServiceGRPCAddress := fmt.Sprintf("%s:%s", config.GRPCHost, config.GRPCPort)

	connection, err := commonTLS.CreateGRPCConnection(emailServiceGRPCAddress, config.TLSEnabled)
	if err != nil {
		return nil, err
	}

	return &EmailService{
		connection,
		config.EmailVerificationEndpoint,
		config.AppName,
	}, nil
}

func (service *EmailService) sendMail(ctx context.Context, dest string, subject string, body string) error {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return err
	}

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

	client := pb_email.NewEmailServiceClient(service.connection)
	res, err := client.SendEmail(clientCtx, req)
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
	subject := fmt.Sprintf("Welcome to %s", service.appName)
	emailVerificationLink := fmt.Sprintf("%suser/%s/email/%s", service.emailVerificationEndpoint, userID, verificationToken)

	body := strings.ReplaceAll(string(verificationEmail), "{firstName}", userName)
	body = strings.ReplaceAll(body, "{appName}", service.appName)
	body = strings.ReplaceAll(body, "{emailVerificationLink}", emailVerificationLink)
	return subject, body, nil
}

// SendVerificationEmail sends a verification email to the given destination
func (service *EmailService) SendVerificationEmail(
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
	passwordResetLink := fmt.Sprintf("%suser/%s/password/reset/%s", service.emailVerificationEndpoint, userID, verificationToken)

	body := strings.ReplaceAll(passwordResetEmail, "{firstName}", userName)
	body = strings.ReplaceAll(body, "{appName}", service.appName)
	body = strings.ReplaceAll(body, "{resetPasswordLink}", passwordResetLink)

	return subject, body
}

// SendPasswordResetEmail sends a verification email to the given destination
func (service *EmailService) SendPasswordResetEmail(ctx context.Context, destination, userName, userID, verificationToken string) error {
	subject, body := service.CreatePasswordResetEmailContent(ctx, destination, userName, userID, verificationToken)
	err := service.sendMail(ctx, destination, subject, body)
	return err
}

// CreateVerificationSuccessEmailContent generates the content for the success notification
func (service *EmailService) CreateVerificationSuccessEmailContent(ctx context.Context, userName string) (string, string) {
	subject := "Email Verification Success"
	body := strings.ReplaceAll(verificationSuccessEmail, "{firstName}", userName)
	return subject, body
}

// SendVerificationSuccessEmail sends an email verification success email
func (service *EmailService) SendVerificationSuccessEmail(ctx context.Context, dest, userName string) error {
	subject, body := service.CreateVerificationSuccessEmailContent(ctx, userName)
	return service.sendMail(ctx, dest, subject, body)
}

// CreateAuthenticationSuccessEmailContent generates the content for the success notification
func (service *EmailService) CreateAuthenticationSuccessEmailContent(ctx context.Context, userName string) (string, string) {
	subject := "Authentication Success"
	body := strings.ReplaceAll(authenticationSuccessEmail, "{firstName}", userName)
	body = strings.ReplaceAll(body, "{appName}", service.appName)
	return subject, body
}

// SendAuthenticationSuccessEmail sends an email verification success email
func (service *EmailService) SendAuthenticationSuccessEmail(ctx context.Context, dest, userName string) error {
	subject, body := service.CreateAuthenticationSuccessEmailContent(ctx, userName)
	return service.sendMail(ctx, dest, subject, body)
}

// CreatePasswordResetSuccessEmailContent generates teh content for the success notification
func (service *EmailService) CreatePasswordResetSuccessEmailContent(ctx context.Context, userName string) (string, string) {
	subject := "Email Verification Success"
	body := strings.ReplaceAll(passwordResetSuccessEmail, "{firstName}", userName)
	return subject, body
}

// SendPasswordResetSuccessEmail sends an email verification success email
func (service *EmailService) SendPasswordResetSuccessEmail(ctx context.Context, dest, userName string) error {
	subject, body := service.CreatePasswordResetSuccessEmailContent(ctx, userName)
	return service.sendMail(ctx, dest, subject, body)
}

// CreatePasswordResetSuccessEmailContent generates teh content for the success notification
func (service *EmailService) CreateDeletedUserEmailContent(ctx context.Context, userName string) (string, string) {
	subject := "Your Account Has Been Successfully Deleted"
	body := strings.ReplaceAll(deleteUserSuccessEmail, "{firstName}", userName)
	body = strings.ReplaceAll(body, "{appName}", service.appName)
	return subject, body
}

// SendPasswordResetSuccessEmail sends an email verification success email
func (service *EmailService) SendDeletedUserEmail(ctx context.Context, dest, userName string) error {
	subject, body := service.CreateDeletedUserEmailContent(ctx, userName)
	return service.sendMail(ctx, dest, subject, body)
}

// Close terminates email service
func (service *EmailService) Close() error {
	return service.connection.Close()
}

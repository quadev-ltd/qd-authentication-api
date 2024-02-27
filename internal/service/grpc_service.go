package service

import (
	"context"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
	commonLogger "github.com/quadev-ltd/qd-common/pkg/log"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/util"
	"qd-authentication-api/pb/gen/go/pb_authentication"
)

// AuthenticationServiceServer is the implementation of the authentication service
type AuthenticationServiceServer struct {
	authenticationService AuthenticationServicer
	pb_authentication.UnimplementedAuthenticationServiceServer
}

// NewAuthenticationServiceServer creates a new authentication service server
func NewAuthenticationServiceServer(
	authenticationService AuthenticationServicer,
) *AuthenticationServiceServer {
	return &AuthenticationServiceServer{
		authenticationService: authenticationService,
	}
}

var _ pb_authentication.AuthenticationServiceServer = &AuthenticationServiceServer{}

// GetPublicKey returns the public key
func (service AuthenticationServiceServer) GetPublicKey(
	ctx context.Context,
	request *pb_authentication.GetPublicKeyRequest,
) (*pb_authentication.GetPublicKeyResponse, error) {
	logger := commonLogger.GetLoggerFromContext(ctx)
	if logger == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error. No logger in context")
	}
	publicKey, err := service.authenticationService.GetPublicKey(ctx)
	if err != nil {
		logger.Error(err, "Failed to get public key")
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	return &pb_authentication.GetPublicKeyResponse{
		PublicKey: publicKey,
	}, nil
}

// Register registers a new user
func (service AuthenticationServiceServer) Register(
	ctx context.Context,
	request *pb_authentication.RegisterRequest,
) (*pb_authentication.RegisterResponse, error) {
	logger := commonLogger.GetLoggerFromContext(ctx)
	if logger == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error. No logger in context")
	}

	var dateOfBirth *time.Time
	if request.DateOfBirth != nil {
		dateOfBirthValue := time.Unix(request.DateOfBirth.GetSeconds(), int64(request.DateOfBirth.GetNanos()))
		dateOfBirth = &dateOfBirthValue
	} else {
		return nil, status.Errorf(codes.InvalidArgument, "Date of birth was not provided")
	}

	registerError := service.authenticationService.Register(
		ctx,
		request.Email,
		request.Password,
		request.FirstName,
		request.LastName,
		dateOfBirth,
	)
	if registerError != nil {
		_, isValidationError := registerError.(validator.ValidationErrors)
		_, isEmailInUseError := registerError.(*model.EmailInUseError)
		_, isNoComplexPasswordError := registerError.(*NoComplexPasswordError)
		_, isEmailError := registerError.(*SendEmailError)
		if isValidationError || isNoComplexPasswordError {
			err := status.Errorf(codes.InvalidArgument, fmt.Sprint("Registration failed: ", registerError.Error()))
			return nil, err
		}
		if isEmailInUseError {
			err := status.Errorf(codes.InvalidArgument, "Registration failed: email already in use")
			return nil, err
		}
		if isEmailError {
			logger.Info("Registration successful")
			return &pb_authentication.RegisterResponse{
				Success: true,
				Message: "Registration successful. However, verification email failed to send",
			}, nil
		}
		logger.Error(registerError, "Registration failed")
		err := status.Errorf(codes.Internal, "Registration failed: internal server error")
		return nil, err
	}
	logger.Info("Registration successful")
	return &pb_authentication.RegisterResponse{
		Success: true,
		Message: "Registration successful",
	}, nil
}

// VerifyEmail verifies the email
func (service AuthenticationServiceServer) VerifyEmail(
	ctx context.Context,
	request *pb_authentication.VerifyEmailRequest,
) (*pb_authentication.VerifyEmailResponse, error) {
	logger := commonLogger.GetLoggerFromContext(ctx)
	if logger == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error. No logger in context")
	}
	verifyEmailError := service.authenticationService.VerifyEmail(ctx, request.VerificationToken)
	if verifyEmailError == nil {
		logger.Info("Email verified successfully")
		return &pb_authentication.VerifyEmailResponse{
			Success: true,
			Message: "Email verified successfully",
		}, nil
	}
	logger.Error(verifyEmailError, "Email verification failed")
	if serviceErr, ok := verifyEmailError.(*Error); ok {
		return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
	}
	return nil, status.Errorf(codes.Internal, "Internal server error")
}

// ResendEmailVerification resends the email verification
func (service AuthenticationServiceServer) ResendEmailVerification(
	ctx context.Context,
	request *pb_authentication.ResendEmailVerificationRequest,
) (*pb_authentication.ResendEmailVerificationResponse, error) {
	logger := commonLogger.GetLoggerFromContext(ctx)
	if logger == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error. No logger in context")
	}
	if !limiter.Allow() {
		logger.Warn("Rate limit exceeded")
		return &pb_authentication.ResendEmailVerificationResponse{
				Success: false,
				Message: "Rate limit exceeded",
			},
			status.Errorf(codes.ResourceExhausted, "Rate limit exceeded")
	}
	email, error := service.authenticationService.VerifyTokenAndDecodeEmail(ctx, request.AuthToken)
	if error != nil {
		if serviceErr, ok := error.(*Error); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		logger.Error(error, "Failed to verify JWT token")
		return nil, status.Errorf(codes.Unauthenticated, "Invalid JWT token")
	}
	error = service.authenticationService.ResendEmailVerification(ctx, *email)
	if error != nil {
		if serviceErr, ok := error.(*Error); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		logger.Error(error, "Failed to resend email verification")
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}
	logger.Info("Email verification sent successfully")
	return &pb_authentication.ResendEmailVerificationResponse{
		Success: true,
		Message: "Email verification sent successfully",
	}, nil
}

// Authenticate authenticates a user
func (service AuthenticationServiceServer) Authenticate(
	ctx context.Context,
	request *pb_authentication.AuthenticateRequest,
) (*pb_authentication.AuthenticateResponse, error) {
	logger := commonLogger.GetLoggerFromContext(ctx)
	if logger == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error. No logger in context")
	}
	authTokens, err := service.authenticationService.Authenticate(ctx, request.Email, request.Password)
	if err != nil {
		err = handleAuthenticationError(err, logger)
		return nil, err
	}
	authenticateResponse := *convertAuthTokensToResponse(authTokens)
	logger.Info("Authentication successful")
	return &authenticateResponse, nil
}

func handleAuthenticationError(err error, logger commonLogger.Loggerer) error {
	switch err.(type) {
	case *model.WrongEmailOrPassword:
		logger.Error(err, "Invalid email or password")
		return status.Errorf(codes.Unauthenticated, "Invalid email or password")
	default:
		logger.Error(err, "Internal error")
		return status.Errorf(codes.Internal, "Internal server error")
	}
}

func convertAuthTokensToResponse(authTokens *model.AuthTokensResponse) *pb_authentication.AuthenticateResponse {
	return &pb_authentication.AuthenticateResponse{
		AuthToken:          authTokens.AuthToken,
		AuthTokenExpiry:    util.ConvertToTimestamp(authTokens.AuthTokenExpiry),
		RefreshToken:       authTokens.RefreshToken,
		RefreshTokenExpiry: util.ConvertToTimestamp(authTokens.RefreshTokenExpiry),
		UserEmail:          authTokens.UserEmail,
	}
}

var limiter = rate.NewLimiter(rate.Limit(1), 5)

// Authenticate authenticates a user
func (service AuthenticationServiceServer) RefreshToken(
	ctx context.Context,
	request *pb_authentication.RefreshTokenRequest,
) (*pb_authentication.AuthenticateResponse, error) {
	logger := commonLogger.GetLoggerFromContext(ctx)
	if logger == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error. No logger in context")
	}
	authTokens, err := service.authenticationService.RefreshToken(ctx, request.Token)
	if err != nil {
		return nil, err
	}
	refreshTokenResponse := *convertAuthTokensToResponse(authTokens)
	logger.Info("Refresh authentication token successful")
	return &refreshTokenResponse, nil
}

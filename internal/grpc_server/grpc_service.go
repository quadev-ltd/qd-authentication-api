package grpc_server

import (
	"context"
	"fmt"
	"qd_authentication_api/internal/log"
	"qd_authentication_api/internal/model"
	authenticationService "qd_authentication_api/internal/service"
	"qd_authentication_api/internal/util"
	"qd_authentication_api/pb/gen/go/pb_authentication"
	"time"

	"github.com/go-playground/validator/v10"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthenticationServiceServer struct {
	AuthenticationService authenticationService.AuthenticationServicer
	pb_authentication.UnimplementedAuthenticationServiceServer
}

var _ pb_authentication.AuthenticationServiceServer = &AuthenticationServiceServer{}

func getLoggerFromContext(ctx context.Context) log.Loggerer {
	if logger, ok := ctx.Value(LoggerKey).(log.Loggerer); ok {
		return logger
	}
	return nil
}

func (service AuthenticationServiceServer) GetPublicKey(
	ctx context.Context,
	request *pb_authentication.GetPublicKeyRequest,
) (*pb_authentication.GetPublicKeyResponse, error) {
	logger := getLoggerFromContext(ctx)
	if logger == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error. No logger in context.")
	}
	publicKey, err := service.AuthenticationService.GetPublicKey()
	if err != nil {
		logger.Error(err, "Failed to get public key")
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	return &pb_authentication.GetPublicKeyResponse{
		PublicKey: publicKey,
	}, nil
}

func (service AuthenticationServiceServer) Register(
	ctx context.Context,
	request *pb_authentication.RegisterRequest,
) (*pb_authentication.RegisterResponse, error) {
	logger := getLoggerFromContext(ctx)
	if logger == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error. No logger in context.")
	}
	dateOfBirth := time.Unix(request.DateOfBirth.GetSeconds(), int64(request.DateOfBirth.GetNanos()))
	registerError := service.AuthenticationService.Register(request.Email, request.Password, request.FirstName, request.LastName, &dateOfBirth)
	if registerError != nil {
		_, isValidationError := registerError.(validator.ValidationErrors)
		_, isEmailInUseError := registerError.(*model.EmailInUseError)
		if isValidationError {
			err := status.Errorf(codes.InvalidArgument, fmt.Sprint("Registration failed: ", registerError.Error()))
			return nil, err
		}
		if isEmailInUseError {
			err := status.Errorf(codes.InvalidArgument, "Registration failed: email already in use")
			return nil, err
		}
		logger.Error(registerError, "Registration failed")
		err := status.Errorf(codes.Internal, "Registration failed: internal server error")
		return nil, err
	}
	logger.Info("Registration successful.")
	return &pb_authentication.RegisterResponse{
		Success: true,
		Message: "Registration successful.",
	}, nil
}

func (service AuthenticationServiceServer) VerifyEmail(
	ctx context.Context,
	request *pb_authentication.VerifyEmailRequest,
) (*pb_authentication.VerifyEmailResponse, error) {
	logger := getLoggerFromContext(ctx)
	if logger == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error. No logger in context.")
	}
	verifyEmailError := service.AuthenticationService.VerifyEmail(request.VerificationToken)
	if verifyEmailError == nil {
		logger.Info("Email verified successfully.")
		return &pb_authentication.VerifyEmailResponse{
			Success: true,
			Message: "Email verified successfully.",
		}, nil
	}
	logger.Error(verifyEmailError, "Email verification failed")
	if serviceErr, ok := verifyEmailError.(*authenticationService.ServiceError); ok {
		return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
	} else {
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}
}

func (service AuthenticationServiceServer) ResendEmailVerification(
	ctx context.Context,
	request *pb_authentication.ResendEmailVerificationRequest,
) (*pb_authentication.ResendEmailVerificationResponse, error) {
	logger := getLoggerFromContext(ctx)
	if logger == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error. No logger in context.")
	}
	if !limiter.Allow() {
		logger.Warn("Rate limit exceeded")
		return &pb_authentication.ResendEmailVerificationResponse{
				Success: false,
				Message: "Rate limit exceeded",
			},
			status.Errorf(codes.ResourceExhausted, "Rate limit exceeded")
	}
	email, error := service.AuthenticationService.VerifyTokenAndDecodeEmail(request.AuthToken)
	if error != nil {
		if serviceErr, ok := error.(*authenticationService.ServiceError); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		logger.Error(error, "Failed to verify JWT token")
		return nil, status.Errorf(codes.Unauthenticated, "Invalid JWT token")
	}
	error = service.AuthenticationService.ResendEmailVerification(*email)
	if error != nil {
		if serviceErr, ok := error.(*authenticationService.ServiceError); ok {
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

func (service AuthenticationServiceServer) Authenticate(
	ctx context.Context,
	request *pb_authentication.AuthenticateRequest,
) (*pb_authentication.AuthenticateResponse, error) {
	logger := getLoggerFromContext(ctx)
	if logger == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error. No logger in context.")
	}
	authTokens, err := service.AuthenticationService.Authenticate(request.Email, request.Password)
	if err != nil {
		err = handleAuthenticationError(err, logger)
		return nil, err
	}
	authenticateResponse := *convertAuthTokensToResponse(authTokens)
	logger.Info("Authentication successful.")
	return &authenticateResponse, nil
}

func handleAuthenticationError(err error, logger log.Loggerer) error {
	switch err.(type) {
	case *model.WrongEmailOrPassword:
		logger.Error(err, "Invalid email or password.")
		return status.Errorf(codes.Unauthenticated, "Invalid email or password.")
	default:
		logger.Error(err, "Internal error.")
		return status.Errorf(codes.Internal, "Internal server error.")
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

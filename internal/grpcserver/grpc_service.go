package grpcserver

import (
	"context"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
	commonLogger "github.com/quadev-ltd/qd-common/pkg/log"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"qd-authentication-api/internal/model"
	servicePkg "qd-authentication-api/internal/service"
	"qd-authentication-api/internal/util"
	"qd-authentication-api/pb/gen/go/pb_authentication"
)

// AuthenticationServiceServer is the implementation of the authentication service
type AuthenticationServiceServer struct {
	userService     servicePkg.UserServicer
	tokenService    servicePkg.TokenServicer
	passwordService servicePkg.PasswordServicer
	pb_authentication.UnimplementedAuthenticationServiceServer
}

// NewAuthenticationServiceServer creates a new authentication service server
func NewAuthenticationServiceServer(
	authenticationService servicePkg.UserServicer,
	tokenService servicePkg.TokenServicer,
	passwordService servicePkg.PasswordServicer,
) *AuthenticationServiceServer {
	return &AuthenticationServiceServer{
		userService:     authenticationService,
		tokenService:    tokenService,
		passwordService: passwordService,
	}
}

var _ pb_authentication.AuthenticationServiceServer = &AuthenticationServiceServer{}

// GetPublicKey returns the public key
func (service AuthenticationServiceServer) GetPublicKey(
	ctx context.Context,
	request *pb_authentication.GetPublicKeyRequest,
) (*pb_authentication.GetPublicKeyResponse, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	publicKey, err := service.tokenService.GetPublicKey(ctx)
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
) (*pb_authentication.BaseResponse, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	var dateOfBirth *time.Time
	if request.DateOfBirth != nil {
		dateOfBirthValue := time.Unix(request.DateOfBirth.GetSeconds(), int64(request.DateOfBirth.GetNanos()))
		dateOfBirth = &dateOfBirthValue
	} else {
		return nil, status.Errorf(codes.InvalidArgument, "Date of birth was not provided")
	}

	registerError := service.userService.Register(
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
		_, isNoComplexPasswordError := registerError.(*servicePkg.NoComplexPasswordError)
		_, isEmailError := registerError.(*servicePkg.SendEmailError)
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
			return &pb_authentication.BaseResponse{
				Success: true,
				Message: "Registration successful. However, verification email failed to send",
			}, nil
		}
		err := status.Errorf(codes.Internal, "Registration failed: internal server error")
		return nil, err
	}
	logger.Info("Registration successful")
	return &pb_authentication.BaseResponse{
		Success: true,
		Message: "Registration successful",
	}, nil
}

// VerifyEmail verifies the email
func (service AuthenticationServiceServer) VerifyEmail(
	ctx context.Context,
	request *pb_authentication.VerifyEmailRequest,
) (*pb_authentication.BaseResponse, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	verifyEmailError := service.userService.VerifyEmail(ctx, request.UserId, request.VerificationToken)
	if verifyEmailError == nil {
		logger.Info("Email verified successfully")
		return &pb_authentication.BaseResponse{
			Success: true,
			Message: "Email verified successfully",
		}, nil
	}
	logger.Error(verifyEmailError, "Email verification failed")
	if serviceErr, ok := verifyEmailError.(*servicePkg.Error); ok {
		return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
	}
	return nil, status.Errorf(codes.Internal, "Internal server error")
}

var resendEmailVerificationLimiter = rate.NewLimiter(rate.Limit(1), 7)

// ResendEmailVerification resends the email verification
func (service AuthenticationServiceServer) ResendEmailVerification(
	ctx context.Context,
	request *pb_authentication.ResendEmailVerificationRequest,
) (*pb_authentication.BaseResponse, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	if !resendEmailVerificationLimiter.Allow() {
		logger.Warn("Rate limit exceeded")
		return &pb_authentication.BaseResponse{
				Success: false,
				Message: "Rate limit exceeded",
			},
			status.Errorf(codes.ResourceExhausted, "Rate limit exceeded")
	}
	claims, err := service.tokenService.VerifyJWTToken(ctx, request.AuthToken)
	if err != nil {
		if serviceErr, ok := err.(*servicePkg.Error); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		logger.Error(err, "Failed to verify JWT token")
		return nil, status.Errorf(codes.Unauthenticated, "Invalid JWT token")
	}
	fmt.Println("\n\n\n\n\n\n\n\n\n Testing claim user id:::", claims.UserID)
	userID, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		logger.Error(err, "Failed to convert user ID to object ID")
		return nil, status.Errorf(codes.InvalidArgument, "Invalid token")
	}
	emailVerificationToken, err := service.tokenService.GenerateEmailVerificationToken(ctx, userID)
	if err != nil {
		logger.Error(err, "Failed to generate email verification token")
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}
	err = service.userService.ResendEmailVerification(ctx, claims.Email, *emailVerificationToken)
	if err != nil {
		if serviceErr, ok := err.(*servicePkg.Error); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		logger.Error(err, "Failed to resend email verification")
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}
	logger.Info("Email verification sent successfully")
	return &pb_authentication.BaseResponse{
		Success: true,
		Message: "Email verification sent successfully",
	}, nil
}

// Authenticate authenticates a user
func (service AuthenticationServiceServer) Authenticate(
	ctx context.Context,
	request *pb_authentication.AuthenticateRequest,
) (*pb_authentication.AuthenticateResponse, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	authTokens, err := service.userService.Authenticate(ctx, request.Email, request.Password)
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

var refreshTokenLimiter = rate.NewLimiter(rate.Limit(1), 5)

// RefreshToken authenticates a user
func (service AuthenticationServiceServer) RefreshToken(
	ctx context.Context,
	request *pb_authentication.RefreshTokenRequest,
) (*pb_authentication.AuthenticateResponse, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	if !refreshTokenLimiter.Allow() {
		logger.Warn("Rate limit exceeded")
		return nil,
			status.Errorf(codes.ResourceExhausted, "Rate limit exceeded")
	}
	authTokens, err := service.userService.RefreshToken(ctx, request.Token)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	refreshTokenResponse := *convertAuthTokensToResponse(authTokens)
	logger.Info("Refresh authentication token successful")
	return &refreshTokenResponse, nil
}

var forgotPasswordLimiter = rate.NewLimiter(rate.Limit(1), 5)

// ForgotPassword sends a forgot password email
func (service AuthenticationServiceServer) ForgotPassword(
	ctx context.Context,
	request *pb_authentication.ForgotPasswordRequest,
) (*pb_authentication.BaseResponse, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	if !forgotPasswordLimiter.Allow() {
		logger.Warn("Rate limit exceeded")
		return &pb_authentication.BaseResponse{
				Success: false,
				Message: "Rate limit exceeded",
			},
			status.Errorf(codes.ResourceExhausted, "Rate limit exceeded")
	}
	error := service.passwordService.ForgotPassword(ctx, request.Email)
	if error != nil {
		if serviceErr, ok := error.(*servicePkg.Error); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		logger.Error(error, "Forgot password failed")
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}
	logger.Info("Forgot password request successful")
	return &pb_authentication.BaseResponse{
		Success: true,
		Message: "Forgot password request successful",
	}, nil
}

// VerifyResetPasswordToken verifies the reset password token
func (service AuthenticationServiceServer) VerifyResetPasswordToken(
	ctx context.Context,
	request *pb_authentication.VerifyResetPasswordTokenRequest,
) (*pb_authentication.VerifyResetPasswordTokenResponse, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	_, err = service.tokenService.VerifyResetPasswordToken(ctx, request.Token)
	if err != nil {
		if serviceErr, ok := err.(*servicePkg.Error); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		logger.Error(err, "Verify reset password token failed")
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}
	logger.Info("Verify reset password token successful")
	return &pb_authentication.VerifyResetPasswordTokenResponse{
		IsValid: true,
		Message: "Verify reset password token successful",
	}, nil
}

// ResetPassword resets the password
func (service AuthenticationServiceServer) ResetPassword(
	ctx context.Context,
	request *pb_authentication.ResetPasswordRequest,
) (*pb_authentication.BaseResponse, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	resetPasswordError := service.passwordService.ResetPassword(ctx, request.Token, request.NewPassword)
	if resetPasswordError != nil {
		if serviceErr, ok := resetPasswordError.(*servicePkg.Error); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		logger.Error(resetPasswordError, "Reset password failed")
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}
	logger.Info("Reset password successful")
	return &pb_authentication.BaseResponse{
		Success: true,
		Message: "Reset password successful",
	}, nil
}

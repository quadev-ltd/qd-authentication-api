package server_grpc

import (
	"context"
	"qd_authentication_api/internal/model"
	"qd_authentication_api/internal/pb"
	"qd_authentication_api/internal/service"
	"qd_authentication_api/internal/util"
	"time"

	"github.com/go-playground/validator/v10"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthenticationServiceServer struct {
	AuthenticationService *service.AuthenticationService
	pb.UnimplementedAuthenticationServiceServer
}

var _ pb.AuthenticationServiceServer = &AuthenticationServiceServer{}

func (service AuthenticationServiceServer) Register(
	ctx context.Context,
	request *pb.RegisterRequest,
) (*pb.RegisterResponse, error) {
	dateOfBirth := time.Unix(request.DateOfBirth.GetSeconds(), int64(request.DateOfBirth.GetNanos()))
	verificationToken, registerError := service.AuthenticationService.Register(request.Email, request.Password, request.FirstName, request.LastName, &dateOfBirth)
	if registerError != nil {
		_, isValidationError := registerError.(validator.ValidationErrors)
		_, isEmailInUseError := registerError.(*model.EmailInUseError)
		if isValidationError || isEmailInUseError {
			err := status.Errorf(codes.InvalidArgument, "Registration failed: Invalid input")
			return nil, err
		}
	}
	return &pb.RegisterResponse{
		Success:           true,
		Message:           "Registration successful",
		VerificationToken: *verificationToken,
	}, nil
}

func (service AuthenticationServiceServer) Authenticate(
	ctx context.Context,
	request *pb.AuthenticateRequest,
) (*pb.AuthenticateResponse, error) {
	authTokens, err := service.AuthenticationService.Authenticate(request.Email, request.Password)
	if err != nil {
		handleAuthenticationError(err)
		return nil, err
	}
	authenticateResponse := *convertAuthTokensToResponse(authTokens)
	return &authenticateResponse, nil
}

func handleAuthenticationError(err error) error {
	switch err.(type) {
	case *model.WrongEmailOrPassword:
		return status.Errorf(codes.Unauthenticated, "Invalid email or password")
	default:
		return status.Errorf(codes.Internal, "Internal server error")
	}
}

func convertAuthTokensToResponse(authTokens *model.AuthTokensResponse) *pb.AuthenticateResponse {
	return &pb.AuthenticateResponse{
		AuthToken:          authTokens.AuthToken,
		AuthTokenExpiry:    util.ConvertToTimestamp(authTokens.AuthTokenExpiry),
		RefreshToken:       authTokens.RefreshToken,
		RefreshTokenExpiry: util.ConvertToTimestamp(authTokens.RefreshTokenExpiry),
		UserEmail:          authTokens.UserEmail,
	}
}

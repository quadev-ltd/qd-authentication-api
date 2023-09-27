package grpc_server

import (
	"context"
	"fmt"
	"qd_authentication_api/internal/model"
	authenticationService "qd_authentication_api/internal/service"
	"qd_authentication_api/internal/util"
	"qd_authentication_api/pb/gen/go/pb_authentication"
	"time"

	"github.com/go-playground/validator/v10"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthenticationServiceServer struct {
	AuthenticationService authenticationService.AuthenticationServicer
	pb_authentication.UnimplementedAuthenticationServiceServer
}

var _ pb_authentication.AuthenticationServiceServer = &AuthenticationServiceServer{}

func (service AuthenticationServiceServer) Register(
	ctx context.Context,
	request *pb_authentication.RegisterRequest,
) (*pb_authentication.RegisterResponse, error) {
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
		err := status.Errorf(codes.Internal, "Registration failed: internal server error")
		return nil, err
	}
	return &pb_authentication.RegisterResponse{
		Success: true,
		Message: "Registration successful",
	}, nil
}

func (service AuthenticationServiceServer) VerifyEmail(
	ctx context.Context,
	request *pb_authentication.VerifyEmailRequest,
) (*pb_authentication.VerifyEmailResponse, error) {
	verifyEmailError := service.AuthenticationService.VerifyEmail(request.VerificationToken)
	if verifyEmailError == nil {
		return &pb_authentication.VerifyEmailResponse{
			Success: true,
			Message: "Email verified successfully",
		}, nil
	}
	if serviceErr, ok := verifyEmailError.(*authenticationService.ServiceError); ok {
		return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
	} else {
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}
}

func (service AuthenticationServiceServer) Authenticate(
	ctx context.Context,
	request *pb_authentication.AuthenticateRequest,
) (*pb_authentication.AuthenticateResponse, error) {
	authTokens, err := service.AuthenticationService.Authenticate(request.Email, request.Password)
	if err != nil {
		err = handleAuthenticationError(err)
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

func convertAuthTokensToResponse(authTokens *model.AuthTokensResponse) *pb_authentication.AuthenticateResponse {
	return &pb_authentication.AuthenticateResponse{
		AuthToken:          authTokens.AuthToken,
		AuthTokenExpiry:    util.ConvertToTimestamp(authTokens.AuthTokenExpiry),
		RefreshToken:       authTokens.RefreshToken,
		RefreshTokenExpiry: util.ConvertToTimestamp(authTokens.RefreshTokenExpiry),
		UserEmail:          authTokens.UserEmail,
	}
}

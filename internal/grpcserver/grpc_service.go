package grpcserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/quadev-ltd/qd-common/pb/gen/go/pb_authentication"
	"github.com/quadev-ltd/qd-common/pb/gen/go/pb_errors"
	commonJWT "github.com/quadev-ltd/qd-common/pkg/jwt"
	commonLogger "github.com/quadev-ltd/qd-common/pkg/log"
	commonToken "github.com/quadev-ltd/qd-common/pkg/token"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"qd-authentication-api/internal/dto"
	"qd-authentication-api/internal/firebase"
	"qd-authentication-api/internal/model"
	servicePkg "qd-authentication-api/internal/service"
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
	userService servicePkg.UserServicer,
	firebaseAuthService firebase.AuthServicer,
	tokenService servicePkg.TokenServicer,
	passwordService servicePkg.PasswordServicer,
) *AuthenticationServiceServer {
	return &AuthenticationServiceServer{
		userService:     userService,
		tokenService:    tokenService,
		passwordService: passwordService,
	}
}

var _ pb_authentication.AuthenticationServiceServer = &AuthenticationServiceServer{}

func createFieldDetailStatusError(
	fieldErrors []*pb_errors.FieldError,
) (*status.Status, error) {
	errStatus := status.New(codes.InvalidArgument, "Registration failed")
	for _, fieldError := range fieldErrors {
		genericDetail, err := anypb.New(fieldError)
		if err != nil {
			return nil, err
		}
		errStatus, err = errStatus.WithDetails(genericDetail)
		if err != nil {
			return nil, err
		}
	}
	return errStatus, nil
}

// GetPublicKey returns the public key
func (service *AuthenticationServiceServer) GetPublicKey(
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
		return nil, status.Errorf(codes.Internal, servicePkg.InternalServerError)
	}

	return &pb_authentication.GetPublicKeyResponse{
		PublicKey: publicKey,
	}, nil
}

// Register registers a new user
func (service *AuthenticationServiceServer) Register(
	ctx context.Context,
	request *pb_authentication.RegisterRequest,
) (*pb_authentication.RegisterResponse, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	var dateOfBirth *time.Time
	if request.DateOfBirth != nil {
		dateOfBirthValue := time.Unix(request.DateOfBirth.GetSeconds(), int64(request.DateOfBirth.GetNanos()))
		dateOfBirth = &dateOfBirthValue
	}

	createdUser, registerError := service.userService.Register(
		ctx,
		strings.ToLower(request.Email),
		request.Password,
		request.FirstName,
		request.LastName,
		dateOfBirth,
	)
	if registerError != nil {
		_, isValidationError := registerError.(validator.ValidationErrors)
		_, isEmailInUseError := registerError.(*model.EmailInUseError)
		_, isNoComplexPasswordError := registerError.(*servicePkg.NoComplexPasswordError)
		if isValidationError || isNoComplexPasswordError || isEmailInUseError {
			var fieldErrors []*pb_errors.FieldError = []*pb_errors.FieldError{}
			if isNoComplexPasswordError {
				fieldErrors = append(fieldErrors, &pb_errors.FieldError{
					Field: "password",
					Error: NonComplexPassword,
				})
			}
			if isEmailInUseError {
				fieldErrors = append(fieldErrors, &pb_errors.FieldError{
					Field: "email",
					Error: EmailAlreadyUsed,
				})
			}
			fieldValidationErrors, err := model.ParseValidationError(registerError)
			if err != nil && len(fieldErrors) == 0 {
				logger.Error(err, "Parsing error")
				status.Errorf(codes.Internal, servicePkg.InternalServerError)
			}

			if fieldValidationErrors != nil {
				fieldErrors = append(fieldErrors, fieldValidationErrors...)
			}

			errStatus, err := createFieldDetailStatusError(fieldErrors)
			if err != nil {
				logger.Error(err, "Failed to create field detail status error")
				return nil, status.Errorf(codes.Internal, servicePkg.InternalServerError)
			}

			return nil, errStatus.Err()
		}
		err := status.Errorf(codes.Internal, "Registration failed: internal server error")
		return nil, err
	}
	emailVerificationToken, err := service.tokenService.GenerateEmailVerificationToken(ctx, createdUser.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error generating email verification token")
	}
	err = service.userService.SendEmailVerification(ctx, createdUser, *emailVerificationToken)

	if err != nil {
		logger.Info("Registration successful")
		return &pb_authentication.RegisterResponse{
			User:    dto.ConvertUserToUserDTO(createdUser),
			Success: true,
			Message: "Registration successful. However, verification email failed to send",
		}, nil
	}

	logger.Info("Registration successful")
	return &pb_authentication.RegisterResponse{
		User:    dto.ConvertUserToUserDTO(createdUser),
		Success: true,
		Message: "Registration successful",
	}, nil
}

// ResendEmailVerification resends the email verification
func (service *AuthenticationServiceServer) ResendEmailVerification(
	ctx context.Context,
	request *pb_authentication.ResendEmailVerificationRequest,
) (*pb_authentication.BaseResponse, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	user, err := service.userService.GetUserProfile(ctx, request.UserID)
	if err != nil {
		if serviceErr, ok := err.(*servicePkg.Error); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		return nil, status.Errorf(codes.Internal, "Error while getting user details")
	}
	if user.AccountStatus == model.AccountStatusVerified {
		return nil, status.Errorf(codes.InvalidArgument, servicePkg.EmailVerifiedError)
	}

	emailVerificationToken, err := service.tokenService.GenerateEmailVerificationToken(ctx, user.ID)
	if err != nil {
		logger.Error(err, "Failed to generate email verification token")
		return nil, status.Errorf(codes.Internal, servicePkg.InternalServerError)
	}
	err = service.userService.ResendEmailVerification(ctx, user, *emailVerificationToken)
	if err != nil {
		if serviceErr, ok := err.(*servicePkg.Error); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		logger.Error(err, "Failed to resend email verification")
		return nil, status.Errorf(codes.Internal, servicePkg.InternalServerError)
	}
	logger.Info("Email verification sent successfully")
	return &pb_authentication.BaseResponse{
		Success: true,
		Message: "Email verification sent successfully",
	}, nil
}

// VerifyEmail verifies the email
func (service *AuthenticationServiceServer) VerifyEmail(
	ctx context.Context,
	request *pb_authentication.VerifyEmailRequest,
) (*pb_authentication.AuthenticateResponse, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	token, err := service.tokenService.
		VerifyEmailVerificationToken(ctx, request.UserID, request.VerificationToken)
	if err != nil {
		if serviceErr, ok := err.(*servicePkg.Error); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		return nil, status.Errorf(codes.Internal, "Email verification token creation failed")
	}
	email, verifyEmailError := service.userService.VerifyEmail(ctx, token)
	if verifyEmailError != nil {
		logger.Error(verifyEmailError, "Email verification failed")
		if serviceErr, ok := verifyEmailError.(*servicePkg.Error); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		return nil, status.Errorf(codes.Internal, "Email verification failed")
	}

	service.tokenService.RemoveUsedToken(ctx, token)

	jwtTokens, err := service.tokenService.GenerateJWTTokens(ctx, *email, request.UserID)
	if err != nil {
		if serviceErr, ok := err.(*servicePkg.Error); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		return nil, status.Errorf(codes.Internal, "Error generating authentication tokens")
	}
	authenticateResponse := *dto.ConvertAuthTokensToResponse(jwtTokens)

	logger.Info("Email verified successfully")
	return &authenticateResponse, nil
}

// Authenticate authenticates a user
func (service *AuthenticationServiceServer) Authenticate(
	ctx context.Context,
	request *pb_authentication.AuthenticateRequest,
) (*pb_authentication.AuthenticateResponse, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	user, err := service.userService.Authenticate(ctx, strings.ToLower(request.Email), request.Password)
	if err != nil {
		err = handleAuthenticationError(err, logger, request.Email)
		return nil, err
	}
	jwtTokens, err := service.tokenService.GenerateJWTTokens(ctx, user.Email, user.ID.Hex())
	if err != nil {
		if serviceErr, ok := err.(*servicePkg.Error); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		return nil, status.Errorf(codes.Internal, "Error generating authentication tokens")
	}
	authenticateResponse := *dto.ConvertAuthTokensToResponse(jwtTokens)
	logger.Info("Authentication successful")
	return &authenticateResponse, nil
}

// AuthenticateWithFirebase uses firebase idToken to authenticate/register the user
func (service *AuthenticationServiceServer) AuthenticateWithFirebase(
	ctx context.Context,
	request *pb_authentication.AuthenticateWithFirebaseRequest,
) (*pb_authentication.AuthenticateResponse, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	firebaseUser, firebaseAuthError := service.userService.AuthenticateWithFirebase(
		ctx,
		request.IdToken,
		request.Email,
		request.FirstName,
		request.LastName,
	)
	if firebaseAuthError != nil {
		if serviceErr, ok := firebaseAuthError.(*servicePkg.Error); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		_, isValidationError := firebaseAuthError.(validator.ValidationErrors)
		if isValidationError {
			fieldValidationErrors, parseError := model.ParseValidationError(firebaseAuthError)
			if parseError != nil {
				logger.Error(parseError, "Firebase authentication failed")
				status.Errorf(codes.Internal, servicePkg.InternalServerError)
			}
			var fieldErrors []*pb_errors.FieldError = []*pb_errors.FieldError{}
			if fieldValidationErrors != nil {
				fieldErrors = append(fieldErrors, fieldValidationErrors...)
			}

			errStatus, err := createFieldDetailStatusError(fieldErrors)
			if err != nil {
				logger.Error(err, "Failed to create field detail status error")
				return nil, status.Errorf(codes.Internal, servicePkg.InternalServerError)
			}

			return nil, errStatus.Err()
		}
		return nil, status.Errorf(codes.Internal, "Error authenticating with Firebase")
	}
	authTokens, err := service.tokenService.GenerateJWTTokens(ctx, firebaseUser.Email, firebaseUser.ID.Hex())
	if err != nil {
		if serviceErr, ok := err.(*servicePkg.Error); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		return nil, status.Errorf(codes.Internal, "Error generating new tokens")
	}
	refreshTokenResponse := *dto.ConvertAuthTokensToResponse(authTokens)
	logger.Info("Firebase authentication successful")
	return &refreshTokenResponse, nil
}

func handleAuthenticationError(err error, logger commonLogger.Loggerer, email string) error {
	switch err.(type) {
	case *model.WrongEmailOrPassword:
		logger.Error(err, fmt.Sprintf("Invalid email or password for user: %s", email))
		return status.Errorf(codes.Unauthenticated, InvalidEmailOrPassword)
	default:
		logger.Error(err, "Internal error")
		return status.Errorf(codes.Internal, servicePkg.InternalServerError)
	}
}

// RefreshToken authenticates a user
func (service *AuthenticationServiceServer) RefreshToken(
	ctx context.Context,
	request *pb_authentication.RefreshTokenRequest,
) (*pb_authentication.AuthenticateResponse, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	claims, err := commonJWT.GetClaimsFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Could not obtain token claims from context")
	}
	if claims.Type != commonToken.RefreshTokenType {
		return nil, status.Errorf(codes.InvalidArgument, "Not a refresh token")
	}
	authTokens, err := service.tokenService.GenerateJWTTokens(ctx, claims.Email, claims.UserID)
	if err != nil {
		if serviceErr, ok := err.(*servicePkg.Error); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		return nil, status.Errorf(codes.Internal, "Error generating new tokens")
	}
	refreshTokenResponse := *dto.ConvertAuthTokensToResponse(authTokens)
	logger.Info("Refresh authentication token successful")
	return &refreshTokenResponse, nil
}

// ForgotPassword sends a forgot password email
func (service *AuthenticationServiceServer) ForgotPassword(
	ctx context.Context,
	request *pb_authentication.ForgotPasswordRequest,
) (*pb_authentication.BaseResponse, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	error := service.passwordService.ForgotPassword(ctx, strings.ToLower(request.Email))
	if error != nil {
		if _, ok := error.(*servicePkg.Error); ok {
			return &pb_authentication.BaseResponse{
				Success: true,
				Message: "Forgot password request successful",
			}, nil
		}
		logger.Error(error, "Forgot password failed")
		return nil, status.Errorf(codes.Internal, "Error trying to send password reset email.")
	}
	logger.Info("Forgot password request successful")
	return &pb_authentication.BaseResponse{
		Success: true,
		Message: "Forgot password request successful",
	}, nil
}

// VerifyResetPasswordToken verifies the reset password token
func (service *AuthenticationServiceServer) VerifyResetPasswordToken(
	ctx context.Context,
	request *pb_authentication.VerifyResetPasswordTokenRequest,
) (*pb_authentication.VerifyResetPasswordTokenResponse, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	_, err = service.tokenService.VerifyResetPasswordToken(ctx, request.UserID, request.Token)
	if err != nil {
		if serviceErr, ok := err.(*servicePkg.Error); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		logger.Error(err, "Verify reset password token failed")
		return nil, status.Errorf(codes.Internal, servicePkg.InternalServerError)
	}
	logger.Info("Verify reset password token successful")
	return &pb_authentication.VerifyResetPasswordTokenResponse{
		IsValid: true,
		Message: "Verify reset password token successful",
	}, nil
}

// ResetPassword resets the password
func (service *AuthenticationServiceServer) ResetPassword(
	ctx context.Context,
	request *pb_authentication.ResetPasswordRequest,
) (*pb_authentication.BaseResponse, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	resetPasswordError := service.passwordService.ResetPassword(
		ctx,
		request.UserID,
		request.Token,
		request.NewPassword,
	)
	if resetPasswordError != nil {
		if serviceErr, ok := resetPasswordError.(*servicePkg.Error); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		logger.Error(resetPasswordError, "Reset password failed")
		return nil, status.Errorf(codes.Internal, servicePkg.InternalServerError)
	}
	logger.Info("Reset password successful")
	return &pb_authentication.BaseResponse{
		Success: true,
		Message: "Reset password successful",
	}, nil
}

// GetUserProfile returns a user's profile details
func (service *AuthenticationServiceServer) GetUserProfile(
	ctx context.Context,
	request *pb_authentication.GetUserProfileRequest,
) (*pb_authentication.GetUserProfileResponse, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	claims, err := commonJWT.GetClaimsFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Could not obtain token claims from context")
	}
	user, err := service.userService.GetUserProfile(ctx, claims.UserID)
	if err != nil {
		if serviceErr, ok := err.(*servicePkg.Error); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		return nil, status.Errorf(codes.Internal, servicePkg.InternalServerError)
	}
	userDTO := dto.ConvertUserToUserDTO(user)
	userProfileResponse := &pb_authentication.GetUserProfileResponse{
		User: userDTO,
	}
	logger.Info("Get user profile successful")
	return userProfileResponse, nil
}

// UpdateUserProfile updates a user's profile details
func (service *AuthenticationServiceServer) UpdateUserProfile(
	ctx context.Context,
	request *pb_authentication.UpdateUserProfileRequest,
) (*pb_authentication.UpdateUserProfileResponse, error) {
	logger, err := commonLogger.GetLoggerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	claims, err := commonJWT.GetClaimsFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Could not obtain token claims from context")
	}
	updatedUser, err := service.userService.UpdateProfileDetails(ctx, claims.UserID, request)
	if err != nil {
		_, isValidationError := err.(validator.ValidationErrors)
		if isValidationError {
			return nil, status.Errorf(codes.InvalidArgument, fmt.Sprint("Update user profile failed: ", err.Error()))
		}
		if serviceErr, ok := err.(*servicePkg.Error); ok {
			return nil, status.Errorf(codes.InvalidArgument, serviceErr.Error())
		}
		return nil, status.Errorf(codes.Internal, servicePkg.InternalServerError)
	}
	logger.Info("Update user profile successful")
	return &pb_authentication.UpdateUserProfileResponse{
		User: dto.ConvertUserToUserDTO(updatedUser),
	}, nil
}

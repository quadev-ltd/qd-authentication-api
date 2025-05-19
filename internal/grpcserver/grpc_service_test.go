package grpcserver

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang/mock/gomock"
	"github.com/quadev-ltd/qd-common/pb/gen/go/pb_authentication"
	commonJWT "github.com/quadev-ltd/qd-common/pkg/jwt"
	"github.com/quadev-ltd/qd-common/pkg/log"
	loggerMock "github.com/quadev-ltd/qd-common/pkg/log/mock"
	commonPB "github.com/quadev-ltd/qd-common/pkg/pb"
	commonToken "github.com/quadev-ltd/qd-common/pkg/token"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/service"
	"qd-authentication-api/internal/service/mock"
)

// TODO: use test suite table driven tests

type GRPCMockParams struct {
	Controller           *gomock.Controller
	MockUserService      *mock.MockUserServicer
	MockTokenService     *mock.MockTokenServicer
	MockPasswordService  *mock.MockPasswordServicer
	MockLogger           *loggerMock.MockLoggerer
	Ctx                  context.Context
	AuthenticationServer AuthenticationServiceServer
}

func initialiseTest(test *testing.T) *GRPCMockParams {
	controller := gomock.NewController(test)

	userServiceMock := mock.NewMockUserServicer(controller)
	tokenServiceMock := mock.NewMockTokenServicer(controller)
	passwordServiceMock := mock.NewMockPasswordServicer(controller)
	loggerMock := loggerMock.NewMockLoggerer(controller)
	ctx := context.WithValue(context.Background(), log.LoggerKey, loggerMock)

	server := AuthenticationServiceServer{
		userService:     userServiceMock,
		tokenService:    tokenServiceMock,
		passwordService: passwordServiceMock,
	}

	return &GRPCMockParams{
		controller,
		userServiceMock,
		tokenServiceMock,
		passwordServiceMock,
		loggerMock,
		ctx,
		server,
	}
}

func TestAuthenticationServiceServer(test *testing.T) {
	// Create a sample registerRequest for testing.
	registerRequest := &pb_authentication.RegisterRequest{
		Email:       "test@example.com",
		Password:    "password",
		FirstName:   "John",
		LastName:    "Doe",
		DateOfBirth: timestamppb.New(time.Now()),
	}

	// Create a sample of AuthenticateWithFirebase request for testing.
	authenticateWithFirebaseRequest := &pb_authentication.AuthenticateWithFirebaseRequest{
		IdToken:   "test-id-token",
		Email:     "test@example.com",
		FirstName: "John",
		LastName:  "Doe",
	}

	// Create a sample request for testing.
	verifyEmailRequest := &pb_authentication.VerifyEmailRequest{
		VerificationToken: "some_verification_token",
		UserID:            primitive.NewObjectID().Hex(),
	}

	authenticateRequest := &pb_authentication.AuthenticateRequest{
		Email:    "test@example.com",
		Password: "password",
	}
	exampleClaims := &commonJWT.TokenClaims{
		UserID: primitive.NewObjectID().Hex(),
		Email:  "test@example.com",
		Type:   commonToken.AuthTokenType,
		Expiry: time.Now().Add(5 * time.Minute),
	}

	firebaseUser := &model.User{
		ID:               primitive.NewObjectID(),
		Email:            "test@email.com",
		FirstName:        "FirstName",
		LastName:         "LastName",
		RegistrationDate: time.Now(),
		AccountStatus:    model.AccountStatusVerified,
		AuthTypes:        []model.AuthenticationType{model.FirebaseAuthType},
	}

	// Register
	test.Run("Registration_Error_Validation", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		mockValidationError := validator.ValidationErrors{
			&mock.CustomValidationError{
				FieldName: "FieldName0",
			},
			&mock.CustomValidationError{
				FieldName: "FieldName1",
			},
			&mock.CustomValidationError{
				FieldName: "FieldName2",
			},
			&mock.CustomValidationError{
				FieldName: "FieldName3",
			},
		}

		mocks.MockUserService.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, mockValidationError)

		response, returnedError := mocks.AuthenticationServer.Register(mocks.Ctx, registerRequest)
		assert.Equal(test, "rpc error: code = InvalidArgument desc = Registration failed", returnedError.Error())
		assert.Nil(test, response)

		errorAmount := len(mockValidationError)
		fieldErrors, err := commonPB.GetFieldValidationErrors(returnedError)
		if err != nil {
			test.Fatal(err)
		}

		assert.Len(test, fieldErrors, errorAmount)
		for i := 0; i < errorAmount; i++ {
			assert.Equal(test, fieldErrors[i].Field, fmt.Sprintf("FieldName%d", i))
			assert.Equal(test, fieldErrors[i].Error, fmt.Sprintf("FieldName%d", i))
		}
	})

	test.Run("Registration_Internal_Server_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		mockValidationError := errors.New("some error")

		mocks.MockUserService.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, mockValidationError)

		response, returnedError := mocks.AuthenticationServer.Register(mocks.Ctx, registerRequest)

		assert.Equal(test, "rpc error: code = Internal desc = Registration failed: internal server error", returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("Registration_Error_Email_In_Use", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		mockEmailInUseError := &model.EmailInUseError{Email: "test@example.com"}

		mocks.MockUserService.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, mockEmailInUseError)

		response, returnedError := mocks.AuthenticationServer.Register(mocks.Ctx, registerRequest)

		assert.Equal(
			test,
			"rpc error: code = InvalidArgument desc = Registration failed",
			returnedError.Error(),
		)
		assert.Nil(test, response)

		fieldErrors, err := commonPB.GetFieldValidationErrors(returnedError)
		if err != nil {
			test.Fatal(err)
		}
		if err != nil {
			test.Fatal(err)
		}

		assert.Equal(test, fieldErrors[0].Field, "email")
		assert.Equal(test, fieldErrors[0].Error, "already_used")
	})

	test.Run("Registration_Error_PasswordComplexity", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		mockEmailInUseError := &service.NoComplexPasswordError{Message: "Password is not complex"}

		mocks.MockUserService.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, mockEmailInUseError)

		response, returnedError := mocks.AuthenticationServer.Register(mocks.Ctx, registerRequest)

		assert.Equal(
			test,
			"rpc error: code = InvalidArgument desc = Registration failed",
			returnedError.Error(),
		)
		assert.Nil(test, response)

		fieldErrors, err := commonPB.GetFieldValidationErrors(returnedError)
		if err != nil {
			test.Fatal(err)
		}

		assert.Equal(test, fieldErrors[0].Field, "password")
		assert.Equal(test, fieldErrors[0].Error, "complex")
	})

	test.Run("Registration_TokenGeneration_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		user := model.NewUser()

		mockServiceError := &service.Error{Message: "some error"}

		mocks.MockUserService.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(user, nil)
		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(
			gomock.Any(),
			user.ID,
		).Return(
			nil,
			mockServiceError,
		)

		response, returnedError := mocks.AuthenticationServer.Register(mocks.Ctx, registerRequest)

		assert.Error(
			test,
			returnedError,
		)
		assert.Equal(
			test,
			"rpc error: code = Internal desc = Error generating email verification token",
			returnedError.Error(),
		)
		assert.Nil(test, response)
	})

	test.Run("Registration_Error_Email_Not_Sent", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		user := model.NewUser()
		testToken := "test-token"
		mockServiceError := &service.SendEmailError{Message: "some error"}

		mocks.MockUserService.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(user, nil)
		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(
			gomock.Any(),
			user.ID,
		).Return(
			&testToken,
			nil,
		)
		mocks.MockUserService.EXPECT().SendEmailVerification(
			gomock.All(),
			gomock.Eq(user),
			testToken,
		).Return(
			mockServiceError,
		)
		mocks.MockLogger.EXPECT().Info("Registration successful")

		response, returnedError := mocks.AuthenticationServer.Register(mocks.Ctx, registerRequest)

		assert.NoError(
			test,
			returnedError,
		)
		assert.Equal(test, response.Message, "Registration successful. However, verification email failed to send")
		assert.True(test, response.Success)
	})

	test.Run("Registration_Success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		successfulResponse := &pb_authentication.BaseResponse{
			Success: true,
			Message: "Registration successful",
		}
		testToken := "test-token"
		user := model.NewUser()
		user.Email = registerRequest.GetEmail()
		user.FirstName = registerRequest.GetFirstName()
		user.LastName = registerRequest.GetLastName()
		user.DateOfBirth = registerRequest.GetDateOfBirth().AsTime()

		mocks.MockUserService.EXPECT().
			Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(user, nil)
		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(
			gomock.Any(),
			user.ID,
		).Return(
			&testToken,
			nil,
		)
		mocks.MockUserService.EXPECT().SendEmailVerification(
			gomock.All(),
			gomock.Eq(user),
			testToken,
		).Return(
			nil,
		)
		mocks.MockLogger.EXPECT().Info("Registration successful")

		response, returnedError := mocks.AuthenticationServer.Register(mocks.Ctx, registerRequest)

		assert.Nil(
			test,
			returnedError,
		)
		assert.Equal(test, response.Message, successfulResponse.Message)
		assert.Equal(test, response.Success, successfulResponse.Success)
		assert.Equal(test, response.User.Email, registerRequest.Email)
		assert.Equal(test, response.User.FirstName, registerRequest.FirstName)
		assert.Equal(test, response.User.LastName, registerRequest.LastName)
	})

	test.Run("EmailVerification_InternalServer_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		mockVerifyEmailError := errors.New("some verification error")
		testTokenObj := model.NewToken("test-hash")
		userObjID, err := primitive.ObjectIDFromHex(verifyEmailRequest.UserID)
		if err != nil {
			test.Fatal(err)
		}
		testTokenObj.UserID = userObjID

		mocks.MockTokenService.EXPECT().
			VerifyEmailVerificationToken(gomock.Any(), verifyEmailRequest.UserID, verifyEmailRequest.VerificationToken).
			Return(testTokenObj, nil)
		mocks.MockUserService.EXPECT().
			VerifyEmail(gomock.Any(), gomock.Eq(testTokenObj)).
			Return(nil, mockVerifyEmailError)
		mocks.MockLogger.EXPECT().Error(mockVerifyEmailError, "Email verification failed")

		response, returnedError := mocks.AuthenticationServer.VerifyEmail(mocks.Ctx, verifyEmailRequest)

		assert.Equal(test, status.Error(codes.Internal, "Email verification failed"), returnedError)
		assert.Nil(test, response)
	})

	test.Run("EmailVerification_Service_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		mockVerifyEmailError := &service.Error{Message: "test-service-error"}
		testTokenObj := model.NewToken("test-hash")
		userObjID, err := primitive.ObjectIDFromHex(verifyEmailRequest.UserID)
		if err != nil {
			test.Fatal(err)
		}
		testTokenObj.UserID = userObjID

		mocks.MockTokenService.EXPECT().
			VerifyEmailVerificationToken(gomock.Any(), verifyEmailRequest.UserID, verifyEmailRequest.VerificationToken).
			Return(testTokenObj, nil)
		mocks.MockUserService.EXPECT().
			VerifyEmail(gomock.Any(), gomock.Eq(testTokenObj)).
			Return(nil, mockVerifyEmailError)
		mocks.MockLogger.EXPECT().Error(mockVerifyEmailError, "Email verification failed")

		response, returnedError := mocks.AuthenticationServer.VerifyEmail(mocks.Ctx, verifyEmailRequest)

		assert.Equal(test, status.Error(codes.InvalidArgument, mockVerifyEmailError.Error()), returnedError)
		assert.Nil(test, response)
	})

	test.Run("VerifyEmail_GenerateTokens_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		mockVerifyEmailError := &service.Error{Message: "test-service-error"}

		testTokenObj := model.NewToken("test-hash")
		userObjID, err := primitive.ObjectIDFromHex(verifyEmailRequest.UserID)
		if err != nil {
			test.Fatal(err)
		}
		user := model.NewUser()
		user.ID = userObjID
		testTokenObj.UserID = userObjID

		mocks.MockTokenService.EXPECT().
			VerifyEmailVerificationToken(gomock.Any(), verifyEmailRequest.UserID, verifyEmailRequest.VerificationToken).
			Return(testTokenObj, nil)
		mocks.MockUserService.EXPECT().
			VerifyEmail(gomock.Any(), gomock.Eq(testTokenObj)).
			Return(&user.Email, nil)
		mocks.MockTokenService.EXPECT().
			RemoveUsedToken(gomock.Any(), gomock.Eq(testTokenObj)).
			Return(nil)
		mocks.MockTokenService.EXPECT().
			GenerateJWTTokens(
				gomock.Any(),
				user.Email,
				user.ID.Hex(),
				true,
			).Return(nil, mockVerifyEmailError)

		response, returnedError := mocks.AuthenticationServer.VerifyEmail(mocks.Ctx, verifyEmailRequest)

		assert.Equal(test, status.Error(codes.InvalidArgument, mockVerifyEmailError.Error()), returnedError)
		assert.Nil(test, response)
	})

	test.Run("VerifyEmail_GenerateTokensInternal_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		mockVerifyEmailError := errors.New("test-service-error")

		testTokenObj := model.NewToken("test-hash")
		userObjID, err := primitive.ObjectIDFromHex(verifyEmailRequest.UserID)
		if err != nil {
			test.Fatal(err)
		}
		user := model.NewUser()
		user.ID = userObjID
		testTokenObj.UserID = userObjID

		mocks.MockTokenService.EXPECT().
			VerifyEmailVerificationToken(gomock.Any(), verifyEmailRequest.UserID, verifyEmailRequest.VerificationToken).
			Return(testTokenObj, nil)
		mocks.MockUserService.EXPECT().
			VerifyEmail(gomock.Any(), gomock.Eq(testTokenObj)).
			Return(&user.Email, nil)
		mocks.MockTokenService.EXPECT().
			RemoveUsedToken(gomock.Any(), gomock.Eq(testTokenObj)).
			Return(nil)
		mocks.MockTokenService.EXPECT().
			GenerateJWTTokens(
				gomock.Any(),
				user.Email,
				user.ID.Hex(),
				true,
			).Return(nil, mockVerifyEmailError)

		response, returnedError := mocks.AuthenticationServer.VerifyEmail(mocks.Ctx, verifyEmailRequest)

		assert.EqualError(test, returnedError, "rpc error: code = Internal desc = Error generating authentication tokens")
		assert.Nil(test, response)
	})

	test.Run("VerifyEmail_Success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		testTokenObj := model.NewToken("test-hash")
		userObjID, err := primitive.ObjectIDFromHex(verifyEmailRequest.UserID)
		if err != nil {
			test.Fatal(err)
		}
		user := model.NewUser()
		user.ID = userObjID
		testTokenObj.UserID = userObjID
		authenticateResponse := &model.AuthTokensResponse{
			AuthToken:          "some_auth_token",
			AuthTokenExpiry:    time.Now(),
			RefreshToken:       "some_refresh_token",
			RefreshTokenExpiry: time.Now(),
			UserEmail:          "test@example.com",
		}

		successfulResponse := &pb_authentication.AuthenticateResponse{
			AuthToken:    authenticateResponse.AuthToken,
			RefreshToken: authenticateResponse.RefreshToken,
		}

		mocks.MockTokenService.EXPECT().
			VerifyEmailVerificationToken(gomock.Any(), verifyEmailRequest.UserID, verifyEmailRequest.VerificationToken).
			Return(testTokenObj, nil)
		mocks.MockUserService.EXPECT().
			VerifyEmail(gomock.Any(), gomock.Eq(testTokenObj)).
			Return(&user.Email, nil)
		mocks.MockTokenService.EXPECT().
			RemoveUsedToken(gomock.Any(), gomock.Eq(testTokenObj)).
			Return(nil)
		mocks.MockTokenService.EXPECT().
			GenerateJWTTokens(
				gomock.Any(),
				user.Email,
				user.ID.Hex(),
				true,
			).Return(authenticateResponse, nil)
		mocks.MockLogger.EXPECT().Info("Email verified successfully")

		response, returnedError := mocks.AuthenticationServer.VerifyEmail(mocks.Ctx, verifyEmailRequest)

		assert.Nil(test, returnedError)
		assert.Equal(test, successfulResponse, response)
	})

	test.Run("Authenticate_InvalidEmailOrPassword_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		invalidEmailOrPasswordError := &model.WrongEmailOrPassword{
			FieldName: "Email",
		}
		expectedError := status.Errorf(codes.Unauthenticated, InvalidEmailOrPassword)

		mocks.MockUserService.EXPECT().
			Authenticate(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, invalidEmailOrPasswordError)
		mocks.MockLogger.EXPECT().Error(invalidEmailOrPasswordError, "Invalid email or password for user: test@example.com")

		response, returnedError := mocks.AuthenticationServer.Authenticate(mocks.Ctx, authenticateRequest)

		assert.Equal(test, expectedError.Error(), returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("Authenticate_InternalServer_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		authenticationError := errors.New("some error")
		expectedError := status.Errorf(codes.Internal, service.InternalServerError)

		mocks.MockUserService.EXPECT().
			Authenticate(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, authenticationError)
		mocks.MockLogger.EXPECT().Error(authenticationError, "Internal error")

		response, returnedError := mocks.AuthenticationServer.Authenticate(mocks.Ctx, authenticateRequest)

		assert.Equal(test, expectedError.Error(), returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("Authenticate_GenerateTokenService_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		user := model.NewUser()
		tokenError := &service.Error{Message: "some error"}

		mocks.MockUserService.EXPECT().
			Authenticate(gomock.Any(), authenticateRequest.Email, authenticateRequest.Password).
			Return(user, nil)
		mocks.MockTokenService.EXPECT().
			GenerateJWTTokens(gomock.Any(), user.Email, user.ID.Hex(), true).
			Return(nil, tokenError)

		response, returnedError := mocks.AuthenticationServer.Authenticate(mocks.Ctx, authenticateRequest)

		assert.EqualError(test, returnedError, "rpc error: code = InvalidArgument desc = some error")
		assert.Nil(test, response)
	})

	test.Run("Authenticate_GenerateToken_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		user := model.NewUser()
		tokenError := errors.New("some error")

		mocks.MockUserService.EXPECT().
			Authenticate(gomock.Any(), authenticateRequest.Email, authenticateRequest.Password).
			Return(user, nil)
		mocks.MockTokenService.EXPECT().
			GenerateJWTTokens(gomock.Any(), user.Email, user.ID.Hex(), true).
			Return(nil, tokenError)

		response, returnedError := mocks.AuthenticationServer.Authenticate(mocks.Ctx, authenticateRequest)

		assert.EqualError(test, returnedError, "rpc error: code = Internal desc = Error generating authentication tokens")
		assert.Nil(test, response)
	})

	test.Run("Authenticate_Success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		user := model.NewUser()

		authenticateResponse := &model.AuthTokensResponse{
			AuthToken:          "some_auth_token",
			AuthTokenExpiry:    time.Now(),
			RefreshToken:       "some_refresh_token",
			RefreshTokenExpiry: time.Now(),
			UserEmail:          "test@example.com",
		}

		successfulResponse := &pb_authentication.AuthenticateResponse{
			AuthToken:    authenticateResponse.AuthToken,
			RefreshToken: authenticateResponse.RefreshToken,
		}

		mocks.MockUserService.EXPECT().
			Authenticate(gomock.Any(), authenticateRequest.Email, authenticateRequest.Password).
			Return(user, nil)
		mocks.MockTokenService.EXPECT().
			GenerateJWTTokens(gomock.Any(), user.Email, user.ID.Hex(), true).
			Return(authenticateResponse, nil)
		mocks.MockLogger.EXPECT().Info("Authentication successful")

		response, returnedError := mocks.AuthenticationServer.Authenticate(mocks.Ctx, authenticateRequest)

		assert.Nil(test, returnedError)
		assert.Equal(test, successfulResponse, response)
	})

	test.Run("AuthenticateWithFirebase_Success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		authenticateResponse := &model.AuthTokensResponse{
			AuthToken:          "some_auth_token",
			AuthTokenExpiry:    time.Now(),
			RefreshToken:       "some_refresh_token",
			RefreshTokenExpiry: time.Now(),
			UserEmail:          "test@example.com",
		}

		successfulResponse := &pb_authentication.AuthenticateResponse{
			AuthToken:    authenticateResponse.AuthToken,
			RefreshToken: authenticateResponse.RefreshToken,
		}

		mocks.MockUserService.EXPECT().AuthenticateWithFirebase(
			gomock.Any(),
			authenticateWithFirebaseRequest.IdToken,
			authenticateWithFirebaseRequest.Email,
			authenticateWithFirebaseRequest.FirstName,
			authenticateWithFirebaseRequest.LastName,
		).Return(firebaseUser, nil)
		mocks.MockTokenService.EXPECT().
			GenerateJWTTokens(gomock.Any(), firebaseUser.Email, firebaseUser.ID.Hex(), false).
			Return(authenticateResponse, nil)

		mocks.MockLogger.EXPECT().Info("Firebase authentication successful")

		response, returnedError := mocks.AuthenticationServer.AuthenticateWithFirebase(
			mocks.Ctx,
			authenticateWithFirebaseRequest,
		)

		assert.Nil(
			test,
			returnedError,
		)
		assert.Nil(test, returnedError)
		assert.Equal(test, successfulResponse, response)
	})

	test.Run("AuthenticateWithFirebase_TokenGeneration_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		tokenError := errors.New("some error")

		mocks.MockUserService.EXPECT().AuthenticateWithFirebase(
			gomock.Any(),
			authenticateWithFirebaseRequest.IdToken,
			authenticateWithFirebaseRequest.Email,
			authenticateWithFirebaseRequest.FirstName,
			authenticateWithFirebaseRequest.LastName,
		).Return(firebaseUser, nil)
		mocks.MockTokenService.EXPECT().
			GenerateJWTTokens(gomock.Any(), firebaseUser.Email, firebaseUser.ID.Hex(), false).
			Return(nil, tokenError)

		response, returnedError := mocks.AuthenticationServer.AuthenticateWithFirebase(
			mocks.Ctx,
			authenticateWithFirebaseRequest,
		)

		assert.EqualError(test, returnedError, "rpc error: code = Internal desc = Error generating new tokens")
		assert.Nil(test, response)
	})

	test.Run("AuthenticateWithFirebase_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		validationErr := errors.New("Email")

		mocks.MockUserService.EXPECT().AuthenticateWithFirebase(
			gomock.Any(),
			authenticateWithFirebaseRequest.IdToken,
			authenticateWithFirebaseRequest.Email,
			authenticateWithFirebaseRequest.FirstName,
			authenticateWithFirebaseRequest.LastName,
		).Return(nil, validationErr)

		response, returnedError := mocks.AuthenticationServer.AuthenticateWithFirebase(
			mocks.Ctx,
			authenticateWithFirebaseRequest,
		)

		assert.Nil(test, response)
		assert.Error(test, returnedError)
		assert.EqualError(test, returnedError, "rpc error: code = Internal desc = Error authenticating with Firebase")
	})

	test.Run("AuthenticateWithFirebase_Validation_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		mockValidationError := validator.ValidationErrors{
			&mock.CustomValidationError{
				FieldName: "FieldName0",
			},
			&mock.CustomValidationError{
				FieldName: "FieldName1",
			},
			&mock.CustomValidationError{
				FieldName: "FieldName2",
			},
			&mock.CustomValidationError{
				FieldName: "FieldName3",
			},
		}

		mocks.MockUserService.EXPECT().AuthenticateWithFirebase(
			gomock.Any(),
			authenticateWithFirebaseRequest.IdToken,
			authenticateWithFirebaseRequest.Email,
			authenticateWithFirebaseRequest.FirstName,
			authenticateWithFirebaseRequest.LastName,
		).Return(nil, mockValidationError)

		response, returnedError := mocks.AuthenticationServer.AuthenticateWithFirebase(
			mocks.Ctx,
			authenticateWithFirebaseRequest,
		)

		assert.Nil(test, response)
		assert.Error(test, returnedError)
		errorAmount := len(mockValidationError)
		fieldErrors, err := commonPB.GetFieldValidationErrors(returnedError)
		if err != nil {
			test.Fatal(err)
		}

		assert.Len(test, fieldErrors, errorAmount)
		for i := 0; i < errorAmount; i++ {
			assert.Equal(test, fieldErrors[i].Field, fmt.Sprintf("FieldName%d", i))
			assert.Equal(test, fieldErrors[i].Error, fmt.Sprintf("FieldName%d", i))
		}
	})

	test.Run("ResendEmailVerification_GetProfile_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		user := model.NewUser()

		expectedError := &service.Error{Message: "test error"}
		mocks.MockUserService.EXPECT().GetUserProfile(
			gomock.Any(),
			user.ID.Hex(),
		).Return(nil, expectedError)

		response, returnedError := mocks.AuthenticationServer.ResendEmailVerification(
			mocks.Ctx,
			&pb_authentication.ResendEmailVerificationRequest{
				UserID: user.ID.Hex(),
			},
		)

		assert.Nil(test, response)
		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = InvalidArgument desc = test error", returnedError.Error())
	})

	test.Run("ResendEmailVerification_InvalidTokenGeneration_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		user := model.NewUser()

		expectedError := &service.Error{Message: "test error"}
		mocks.MockUserService.EXPECT().GetUserProfile(
			gomock.Any(),
			user.ID.Hex(),
		).Return(user, nil)
		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(
			gomock.Any(),
			gomock.Eq(user.ID),
		).Return(nil, expectedError)
		mocks.MockLogger.EXPECT().Error(expectedError, "Failed to generate email verification token")

		response, returnedError := mocks.AuthenticationServer.ResendEmailVerification(
			mocks.Ctx,
			&pb_authentication.ResendEmailVerificationRequest{
				UserID: user.ID.Hex(),
			},
		)

		assert.Nil(test, response)
		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = internal_server_error", returnedError.Error())
	})

	test.Run("ResendEmailVerification_ResendEmail_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testToken := "test-token"
		user := model.NewUser()

		expectedError := &service.Error{Message: "test error"}

		mocks.MockUserService.EXPECT().GetUserProfile(
			gomock.Any(),
			user.ID.Hex(),
		).Return(user, nil)
		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(
			gomock.Any(),
			user.ID,
		).Return(&testToken, nil)
		mocks.MockUserService.EXPECT().
			ResendEmailVerification(gomock.Any(), user, testToken).
			Return(expectedError)

		response, returnedError := mocks.AuthenticationServer.ResendEmailVerification(
			mocks.Ctx,
			&pb_authentication.ResendEmailVerificationRequest{
				UserID: user.ID.Hex(),
			},
		)

		assert.Nil(test, response)
		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = InvalidArgument desc = test error", returnedError.Error())
	})

	test.Run("ResendEmailVerification_InternalServerError", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testToken := "test-token"
		user := model.NewUser()

		expectedError := errors.New("test error")
		mocks.MockUserService.EXPECT().GetUserProfile(
			gomock.Any(),
			user.ID.Hex(),
		).Return(user, nil)
		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(
			gomock.Any(),
			user.ID,
		).Return(&testToken, nil)
		mocks.MockUserService.EXPECT().
			ResendEmailVerification(gomock.Any(), user, testToken).
			Return(expectedError)
		mocks.MockLogger.EXPECT().Error(expectedError, "Failed to resend email verification")

		response, returnedError := mocks.AuthenticationServer.ResendEmailVerification(
			mocks.Ctx,
			&pb_authentication.ResendEmailVerificationRequest{
				UserID: user.ID.Hex(),
			},
		)

		assert.Nil(test, response)
		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = internal_server_error", returnedError.Error())
	})

	test.Run("ResendEmailVerification_Success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testToken := "test-token"
		user := model.NewUser()

		mocks.MockTokenService.EXPECT().GenerateEmailVerificationToken(
			gomock.Any(),
			user.ID,
		).Return(&testToken, nil)
		mocks.MockUserService.EXPECT().
			ResendEmailVerification(gomock.Any(), user, testToken).
			Return(nil)
		mocks.MockUserService.EXPECT().
			GetUserProfile(gomock.Any(), user.ID.Hex()).
			Return(user, nil)
		mocks.MockLogger.EXPECT().Info("Email verification sent successfully")

		response, returnedError := mocks.AuthenticationServer.ResendEmailVerification(
			mocks.Ctx,
			&pb_authentication.ResendEmailVerificationRequest{
				UserID: user.ID.Hex(),
			},
		)

		assert.Nil(test, returnedError)
		assert.Equal(test, true, response.Success)
		assert.Equal(test, "Email verification sent successfully", response.Message)
	})

	// RefreshToken
	test.Run("RefreshToken_Success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		resultTokens := &model.AuthTokensResponse{
			AuthToken:          "auth-token",
			AuthTokenExpiry:    time.Now(),
			RefreshToken:       "refresh-token",
			RefreshTokenExpiry: time.Now(),
			UserEmail:          "test@user.com",
		}
		refreshClaims := &commonJWT.TokenClaims{
			Email:  exampleClaims.Email,
			Type:   commonToken.RefreshTokenType,
			Expiry: exampleClaims.Expiry,
			UserID: exampleClaims.UserID,
		}
		mocks.MockTokenService.EXPECT().
			GenerateJWTTokens(gomock.Any(), exampleClaims.Email, exampleClaims.UserID, false).
			Return(resultTokens, nil)
		mocks.MockLogger.EXPECT().Info("Refresh authentication token successful")

		ctxWithClaims := NewContextWithClaims(mocks.Ctx, refreshClaims)
		response, returnedError := mocks.AuthenticationServer.RefreshToken(
			ctxWithClaims,
			&pb_authentication.RefreshTokenRequest{},
		)

		assert.Nil(test, returnedError)
		assert.Equal(test, resultTokens.AuthToken, response.AuthToken)
		assert.Equal(test, resultTokens.RefreshToken, response.RefreshToken)
	})

	test.Run("RefreshToken_Generation_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		mockedError := errors.New("test-error")
		refreshClaims := &commonJWT.TokenClaims{
			Email:  exampleClaims.Email,
			Type:   commonToken.RefreshTokenType,
			Expiry: exampleClaims.Expiry,
			UserID: exampleClaims.UserID,
		}
		mocks.MockTokenService.EXPECT().
			GenerateJWTTokens(gomock.Any(), exampleClaims.Email, exampleClaims.UserID, false).
			Return(nil, mockedError)

		ctxWithClaims := NewContextWithClaims(mocks.Ctx, refreshClaims)
		response, returnedError := mocks.AuthenticationServer.RefreshToken(
			ctxWithClaims,
			&pb_authentication.RefreshTokenRequest{},
		)

		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = Error generating new tokens", returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("RefreshToken_GenerationService_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		mockedError := &service.Error{Message: "test-error"}
		refreshClaims := &commonJWT.TokenClaims{
			Email:  exampleClaims.Email,
			Type:   commonToken.RefreshTokenType,
			Expiry: exampleClaims.Expiry,
			UserID: exampleClaims.UserID,
		}
		mocks.MockTokenService.EXPECT().
			GenerateJWTTokens(gomock.Any(), exampleClaims.Email, exampleClaims.UserID, false).
			Return(nil, mockedError)

		ctxWithClaims := NewContextWithClaims(mocks.Ctx, refreshClaims)
		response, returnedError := mocks.AuthenticationServer.RefreshToken(
			ctxWithClaims,
			&pb_authentication.RefreshTokenRequest{},
		)

		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = InvalidArgument desc = test-error", returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("RefreshToken_Claims_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		response, returnedError := mocks.AuthenticationServer.RefreshToken(mocks.Ctx, &pb_authentication.RefreshTokenRequest{})

		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = Could not obtain token claims from context", returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("RefreshToken_MissingLogger_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		response, returnedError := mocks.AuthenticationServer.RefreshToken(
			context.Background(),
			&pb_authentication.RefreshTokenRequest{},
		)

		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = Logger not found in context", returnedError.Error())
		assert.Nil(test, response)
	})

	// ForgotPassword
	test.Run("ForgotPassword_Success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testEmail := "test@email.com"

		mocks.MockPasswordService.EXPECT().ForgotPassword(
			gomock.Any(),
			testEmail,
		).Return(nil)
		mocks.MockLogger.EXPECT().Info("Forgot password request successful")

		response, returnedError := mocks.AuthenticationServer.ForgotPassword(mocks.Ctx, &pb_authentication.ForgotPasswordRequest{
			Email: testEmail,
		})

		assert.Nil(test, returnedError)
		assert.Equal(test, "Forgot password request successful", response.Message)
		assert.True(test, response.Success)
	})

	test.Run("ForgotPassword_Error_ReturnsSuccess", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testEmail := "test@email.com"
		exampleError := &service.Error{
			Message: "example of expected error",
		}

		mocks.MockPasswordService.EXPECT().ForgotPassword(gomock.Any(),
			testEmail,
		).Return(exampleError)

		response, returnedError := mocks.AuthenticationServer.ForgotPassword(
			mocks.Ctx,
			&pb_authentication.ForgotPasswordRequest{
				Email: testEmail,
			},
		)

		assert.Nil(test, returnedError)
		assert.Equal(test, "Forgot password request successful", response.Message)
		assert.True(test, response.Success)
	})

	test.Run("ForgotPassword_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testEmail := "test@email.com"
		exampleError := errors.New("test-error")

		mocks.MockPasswordService.EXPECT().ForgotPassword(gomock.Any(),
			testEmail,
		).Return(exampleError)
		mocks.MockLogger.EXPECT().Error(exampleError, "Forgot password failed")

		response, returnedError := mocks.AuthenticationServer.ForgotPassword(mocks.Ctx, &pb_authentication.ForgotPasswordRequest{
			Email: testEmail,
		})

		assert.Error(test, returnedError)
		assert.Nil(test, response)
		assert.Equal(test, "rpc error: code = Internal desc = Error trying to send password reset email.", returnedError.Error())
	})

	test.Run("ForgotPassword_MissingLogger_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testEmail := "test@email.com"

		response, returnedError := mocks.AuthenticationServer.ForgotPassword(context.Background(), &pb_authentication.ForgotPasswordRequest{
			Email: testEmail,
		})

		assert.Error(test, returnedError)
		assert.Nil(test, response)
		assert.Equal(test, "rpc error: code = Internal desc = Logger not found in context", returnedError.Error())
	})

	// VerifyResetPasswordToken
	test.Run("VerifyResetPasswordToken_Success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "test@email.com"
		userID := primitive.NewObjectID().Hex()

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(
			gomock.Any(),
			userID,
			testTokenValue,
		).Return(&model.Token{TokenHash: testTokenValue}, nil)
		mocks.MockLogger.EXPECT().Info("Verify reset password token successful")

		response, returnedError := mocks.AuthenticationServer.VerifyResetPasswordToken(mocks.Ctx, &pb_authentication.VerifyResetPasswordTokenRequest{
			UserID: userID,
			Token:  testTokenValue,
		})

		assert.Nil(test, returnedError)
		assert.Equal(test, "Verify reset password token successful", response.Message)
		assert.True(test, response.IsValid)
	})

	test.Run("VerifyResetPasswordToken_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "test@email.com"
		exampleError := errors.New("test-error")
		userID := primitive.NewObjectID().Hex()

		mocks.MockTokenService.EXPECT().VerifyResetPasswordToken(
			gomock.Any(),
			userID,
			testTokenValue,
		).Return(nil, exampleError)
		mocks.MockLogger.EXPECT().Error(exampleError, "Verify reset password token failed")

		response, returnedError := mocks.AuthenticationServer.VerifyResetPasswordToken(mocks.Ctx, &pb_authentication.VerifyResetPasswordTokenRequest{
			UserID: userID,
			Token:  testTokenValue,
		})

		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = internal_server_error", returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("VerifyResetPasswordToken_MissingLogger_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "test@email.com"
		userID := primitive.NewObjectID().Hex()

		response, returnedError := mocks.AuthenticationServer.VerifyResetPasswordToken(context.Background(), &pb_authentication.VerifyResetPasswordTokenRequest{
			UserID: userID,
			Token:  testTokenValue,
		})

		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = Logger not found in context", returnedError.Error())
		assert.Nil(test, response)
	})

	// ResetPassword
	test.Run("ResetPassword_Success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "token-value"
		testPassword := "test-password"
		userID := primitive.NewObjectID().Hex()
		mocks.MockPasswordService.EXPECT().ResetPassword(
			gomock.Any(),
			userID,
			testTokenValue,
			testPassword,
		).Return(nil)
		mocks.MockLogger.EXPECT().Info("Reset password successful")

		response, returnedError := mocks.AuthenticationServer.ResetPassword(mocks.Ctx, &pb_authentication.ResetPasswordRequest{
			UserID:      userID,
			Token:       testTokenValue,
			NewPassword: testPassword,
		})

		assert.Nil(test, returnedError)
		assert.Equal(test, "Reset password successful", response.Message)
		assert.True(test, response.Success)
	})

	test.Run("ResetPassword_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "token-value"
		testPassword := "test-password"
		exampleError := errors.New("test-error")
		userID := primitive.NewObjectID().Hex()
		mocks.MockPasswordService.EXPECT().ResetPassword(
			gomock.Any(),
			userID,
			testTokenValue,
			testPassword,
		).Return(exampleError)
		mocks.MockLogger.EXPECT().Error(exampleError, "Reset password failed")

		response, returnedError := mocks.AuthenticationServer.ResetPassword(mocks.Ctx, &pb_authentication.ResetPasswordRequest{
			UserID:      userID,
			Token:       testTokenValue,
			NewPassword: testPassword,
		})

		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = internal_server_error", returnedError.Error())
		assert.Nil(test, response)
	})

	test.Run("ResetPassword_MissingLogger_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		testTokenValue := "token-value"
		testPassword := "test-password"

		response, returnedError := mocks.AuthenticationServer.ResetPassword(context.Background(), &pb_authentication.ResetPasswordRequest{
			Token:       testTokenValue,
			NewPassword: testPassword,
		})

		assert.Error(test, returnedError)
		assert.Equal(test, "rpc error: code = Internal desc = Logger not found in context", returnedError.Error())
		assert.Nil(test, response)
	})

	// GetUserProfile
	test.Run("GetUserProfile_Success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		user := model.NewUser()
		userObjID, err := primitive.ObjectIDFromHex(exampleClaims.UserID)
		if err != nil {
			test.Fatal(err)
		}
		user.ID = userObjID

		mocks.MockUserService.EXPECT().GetUserProfile(
			gomock.Any(),
			exampleClaims.UserID,
		).Return(
			user,
			nil,
		)
		mocks.MockLogger.EXPECT().Info("Get user profile successful")

		ctxWithClaims := NewContextWithClaims(mocks.Ctx, exampleClaims)
		getUserProfileResponse, err := mocks.AuthenticationServer.GetUserProfile(
			ctxWithClaims,
			&pb_authentication.GetUserProfileRequest{},
		)

		assert.NoError(test, err)
		assert.Equal(test, user.ID.Hex(), getUserProfileResponse.User.UserID)
		assert.Equal(test, user.Email, getUserProfileResponse.User.Email)
		assert.Equal(test, user.FirstName, getUserProfileResponse.User.FirstName)
		assert.Equal(test, user.LastName, getUserProfileResponse.User.LastName)
		assert.Equal(test, user.DateOfBirth.Unix(), getUserProfileResponse.User.DateOfBirth.AsTime().Unix())
		assert.Equal(test, user.RegistrationDate.Unix(), getUserProfileResponse.User.RegistrationDate.AsTime().Unix())
	})

	test.Run("GetUserProfile_SerService_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		user := model.NewUser()
		mockedError := &service.Error{
			Message: "test-error",
		}

		userObjID, err := primitive.ObjectIDFromHex(exampleClaims.UserID)
		if err != nil {
			test.Fatal(err)
		}
		user.ID = userObjID

		mocks.MockUserService.EXPECT().GetUserProfile(
			gomock.Any(),
			exampleClaims.UserID,
		).Return(
			nil,
			mockedError,
		)

		ctxWithClaims := NewContextWithClaims(mocks.Ctx, exampleClaims)
		getUserProfileResponse, err := mocks.AuthenticationServer.GetUserProfile(
			ctxWithClaims,
			&pb_authentication.GetUserProfileRequest{},
		)

		assert.Error(test, err)
		assert.Nil(test, getUserProfileResponse)
		assert.EqualError(test, err, "rpc error: code = InvalidArgument desc = test-error")
	})

	test.Run("GetUserProfile_General_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		user := model.NewUser()
		mockedError := errors.New("test-error")

		userObjID, err := primitive.ObjectIDFromHex(exampleClaims.UserID)
		if err != nil {
			test.Fatal(err)
		}
		user.ID = userObjID

		mocks.MockUserService.EXPECT().GetUserProfile(
			gomock.Any(),
			exampleClaims.UserID,
		).Return(
			nil,
			mockedError,
		)
		ctxWithClaims := NewContextWithClaims(mocks.Ctx, exampleClaims)
		getUserProfileResponse, err := mocks.AuthenticationServer.GetUserProfile(
			ctxWithClaims,
			&pb_authentication.GetUserProfileRequest{},
		)

		assert.Error(test, err)
		assert.Nil(test, getUserProfileResponse)
		assert.EqualError(test, err, "rpc error: code = Internal desc = internal_server_error")
	})

	test.Run("GetUserProfile_Claims_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		user := model.NewUser()

		userObjID, err := primitive.ObjectIDFromHex(exampleClaims.UserID)
		if err != nil {
			test.Fatal(err)
		}
		user.ID = userObjID

		getUserProfileResponse, err := mocks.AuthenticationServer.GetUserProfile(
			mocks.Ctx,
			&pb_authentication.GetUserProfileRequest{},
		)

		assert.Error(test, err)
		assert.Nil(test, getUserProfileResponse)
		assert.EqualError(test, err, "rpc error: code = Internal desc = Could not obtain token claims from context")
	})

	test.Run("UpdateUserProfile_Success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		user := model.NewUser()
		userObjID, err := primitive.ObjectIDFromHex(exampleClaims.UserID)
		if err != nil {
			test.Fatal(err)
		}
		user.ID = userObjID
		newFirstName := "John"
		newLastName := "Doe"
		newDOB := timestamppb.Now()
		user.FirstName = newFirstName
		user.LastName = newLastName
		user.DateOfBirth = newDOB.AsTime()
		updateRequest := &pb_authentication.UpdateUserProfileRequest{
			FirstName:   newFirstName,
			LastName:    newLastName,
			DateOfBirth: newDOB,
		}

		mocks.MockUserService.EXPECT().UpdateProfileDetails(
			gomock.Any(),
			exampleClaims.UserID,
			gomock.Eq(updateRequest),
		).Return(
			user,
			nil,
		)
		mocks.MockLogger.EXPECT().Info("Update user profile successful")
		ctxWithClaims := NewContextWithClaims(mocks.Ctx, exampleClaims)
		updateUserProfileResponse, err := mocks.AuthenticationServer.UpdateUserProfile(
			ctxWithClaims,
			updateRequest,
		)

		assert.NoError(test, err)
		assert.Equal(test, user.ID.Hex(), updateUserProfileResponse.User.UserID)
		assert.Equal(test, user.Email, updateUserProfileResponse.User.Email)
		assert.Equal(test, newFirstName, updateUserProfileResponse.User.FirstName)
		assert.Equal(test, newLastName, updateUserProfileResponse.User.LastName)
		assert.Equal(test, newDOB, updateUserProfileResponse.User.DateOfBirth)
	})

	test.Run("UpdateUserProfile_Update_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		mockedError := errors.New("test-error")
		newFirstName := "John"
		newLastName := "Doe"
		newDOB := timestamppb.Now()
		updateRequest := &pb_authentication.UpdateUserProfileRequest{
			FirstName:   newFirstName,
			LastName:    newLastName,
			DateOfBirth: newDOB,
		}

		mocks.MockUserService.EXPECT().UpdateProfileDetails(
			gomock.Any(),
			exampleClaims.UserID,
			gomock.Eq(updateRequest),
		).Return(
			nil,
			mockedError,
		)
		ctxWithClaims := NewContextWithClaims(mocks.Ctx, exampleClaims)
		updateUserProfileResponse, err := mocks.AuthenticationServer.UpdateUserProfile(
			ctxWithClaims,
			updateRequest,
		)

		assert.Error(test, err)
		assert.Nil(test, updateUserProfileResponse)
		assert.EqualError(test, err, "rpc error: code = Internal desc = internal_server_error")
	})

	test.Run("UpdateUserProfile_Claims_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()
		newFirstName := "John"
		newLastName := "Doe"
		newDOB := timestamppb.Now()
		updateRequest := &pb_authentication.UpdateUserProfileRequest{
			FirstName:   newFirstName,
			LastName:    newLastName,
			DateOfBirth: newDOB,
		}

		updateUserProfileResponse, err := mocks.AuthenticationServer.UpdateUserProfile(
			mocks.Ctx,
			updateRequest,
		)

		assert.Error(test, err)
		assert.Nil(test, updateUserProfileResponse)
		assert.EqualError(test, err, "rpc error: code = Internal desc = Could not obtain token claims from context")
	})

	test.Run("DeleteAccount_Success", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		// Mock the claims
		ctxWithClaims := NewContextWithClaims(
			mocks.Ctx,
			&commonJWT.TokenClaims{
				UserID: exampleClaims.UserID,
				Email:  exampleClaims.Email,
				Type:   commonToken.AuthTokenType,
			},
		)

		// Expect userService.DeleteUser to succeed
		mocks.MockUserService.EXPECT().
			DeleteUser(gomock.Any(), exampleClaims.UserID).
			Return(nil)

		// Expect tokenService.RemoveUnusedTokens to succeed
		mocks.MockTokenService.EXPECT().
			RemoveUnusedTokens(gomock.Any(), exampleClaims.UserID, commonToken.AllTokenType).
			Return(nil)

		// Expect a success log message
		mocks.MockLogger.EXPECT().Info(
			fmt.Sprintf("User %s account deleted successfully", exampleClaims.Email),
		)

		resp, err := mocks.AuthenticationServer.DeleteAccount(ctxWithClaims, &pb_authentication.DeleteAccountRequest{})
		assert.NoError(test, err)
		assert.NotNil(test, resp)
		assert.True(test, resp.Success)
		assert.Equal(test, "User account deleted successfully", resp.Message)
	})

	test.Run("DeleteAccount_Claims_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		resp, err := mocks.AuthenticationServer.DeleteAccount(
			mocks.Ctx, // Context WITHOUT the needed claims
			&pb_authentication.DeleteAccountRequest{},
		)

		assert.Error(test, err)
		assert.Nil(test, resp)
		assert.EqualError(test, err, "rpc error: code = Internal desc = Could not obtain token claims from context")
	})

	test.Run("DeleteAccount_MissingLogger_Error", func(test *testing.T) {
		mocks := initialiseTest(test)
		resp, err := mocks.AuthenticationServer.DeleteAccount(
			context.Background(),
			&pb_authentication.DeleteAccountRequest{},
		)

		assert.Error(test, err)
		assert.Nil(test, resp)
		assert.EqualError(test, err, "rpc error: code = Internal desc = Logger not found in context")
	})

	test.Run("DeleteAccount_UserService_Error_AsServicePkgError", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		expectedError := &service.Error{Message: "service-error"}
		ctxWithClaims := NewContextWithClaims(
			mocks.Ctx,
			&commonJWT.TokenClaims{
				UserID: exampleClaims.UserID,
				Email:  exampleClaims.Email,
				Type:   commonToken.AuthTokenType,
			},
		)

		// userService.DeleteUser returns a service.Error
		mocks.MockUserService.EXPECT().
			DeleteUser(gomock.Any(), exampleClaims.UserID).
			Return(expectedError)

		resp, err := mocks.AuthenticationServer.DeleteAccount(
			ctxWithClaims,
			&pb_authentication.DeleteAccountRequest{},
		)

		assert.Nil(test, resp)
		assert.Error(test, err)
		assert.EqualError(test, err, "rpc error: code = InvalidArgument desc = service-error")
	})

	test.Run("DeleteAccount_UserService_GeneralError", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		expectedError := errors.New("general-error")
		ctxWithClaims := NewContextWithClaims(
			mocks.Ctx,
			&commonJWT.TokenClaims{
				UserID: exampleClaims.UserID,
				Email:  exampleClaims.Email,
				Type:   commonToken.AuthTokenType,
			},
		)

		// userService.DeleteUser returns a general error
		mocks.MockUserService.EXPECT().
			DeleteUser(gomock.Any(), exampleClaims.UserID).
			Return(expectedError)

		resp, err := mocks.AuthenticationServer.DeleteAccount(
			ctxWithClaims,
			&pb_authentication.DeleteAccountRequest{},
		)

		assert.Nil(test, resp)
		assert.Error(test, err)
		assert.EqualError(test, err, "rpc error: code = Internal desc = internal_server_error")
	})

	test.Run("DeleteAccount_RemoveUnusedTokens_Error_AsServicePkgError", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		ctxWithClaims := NewContextWithClaims(
			mocks.Ctx,
			&commonJWT.TokenClaims{
				UserID: exampleClaims.UserID,
				Email:  exampleClaims.Email,
				Type:   commonToken.AuthTokenType,
			},
		)

		// userService.DeleteUser is successful
		mocks.MockUserService.EXPECT().
			DeleteUser(gomock.Any(), exampleClaims.UserID).
			Return(nil)

		// tokenService.RemoveUnusedTokens returns a service.Error
		expectedError := &service.Error{Message: "service-error"}
		mocks.MockTokenService.EXPECT().
			RemoveUnusedTokens(gomock.Any(), exampleClaims.UserID, commonToken.AllTokenType).
			Return(expectedError)

		resp, err := mocks.AuthenticationServer.DeleteAccount(
			ctxWithClaims,
			&pb_authentication.DeleteAccountRequest{},
		)

		assert.Nil(test, resp)
		assert.Error(test, err)
		assert.EqualError(test, err, "rpc error: code = InvalidArgument desc = service-error")
	})

	test.Run("DeleteAccount_RemoveUnusedTokens_GeneralError", func(test *testing.T) {
		mocks := initialiseTest(test)
		defer mocks.Controller.Finish()

		ctxWithClaims := NewContextWithClaims(
			mocks.Ctx,
			&commonJWT.TokenClaims{
				UserID: exampleClaims.UserID,
				Email:  exampleClaims.Email,
				Type:   commonToken.AuthTokenType,
			},
		)

		// userService.DeleteUser is successful
		mocks.MockUserService.EXPECT().
			DeleteUser(gomock.Any(), exampleClaims.UserID).
			Return(nil)

		// tokenService.RemoveUnusedTokens returns a general error
		expectedError := errors.New("general-error")
		mocks.MockTokenService.EXPECT().
			RemoveUnusedTokens(gomock.Any(), exampleClaims.UserID, commonToken.AllTokenType).
			Return(expectedError)

		resp, err := mocks.AuthenticationServer.DeleteAccount(
			ctxWithClaims,
			&pb_authentication.DeleteAccountRequest{},
		)

		assert.Nil(test, resp)
		assert.Error(test, err)
		assert.EqualError(test, err, "rpc error: code = Internal desc = internal_server_error")
	})
}

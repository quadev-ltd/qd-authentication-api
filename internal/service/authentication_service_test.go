package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt"
	"github.com/golang/mock/gomock"
	"github.com/quadev-ltd/qd-common/pkg/log"
	loggerMock "github.com/quadev-ltd/qd-common/pkg/log/mock"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"

	jwtSignerMock "qd-authentication-api/internal/jwt/mock"
	"qd-authentication-api/internal/model"
	repositoryMock "qd-authentication-api/internal/repository/mock"
	serviceMock "qd-authentication-api/internal/service/mock"
)

const (
	testEmail     = "test@example.com"
	testPassword  = "Password123!"
	testFirstName = "John"
	testLastName  = "Doe"
	invalidEmail  = "invalid-email"
)

var (
	testDateOfBirth = time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	token           = "token"
	refreshToken    = "refreshToken"
)

func newUser() *model.User {
	RefreshTokens := []model.RefreshToken{
		{
			Token:     refreshToken,
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
			Revoked:   false,
		},
	}
	return &model.User{
		Email:            "test@example.com",
		PasswordHash:     "hash",
		PasswordSalt:     "7jQQnlalvK1E0iDzugF18ewa1Auf7R71Dr6OWnJbZbI=",
		FirstName:        "Test",
		LastName:         "User",
		DateOfBirth:      time.Now(),
		RegistrationDate: time.Now(),
		LastLoginDate:    time.Now(),
		AccountStatus:    model.AccountStatusUnverified,
		RefreshTokens:    RefreshTokens,
	}
}

func newToken() *model.Token {
	return &model.Token{
		Token:     "test_token_example",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(2 * time.Hour),
		Revoked:   false,
		Type:      model.EmailVerificationTokenType,
		UserID:    primitive.NewObjectID(),
	}
}

// TODO try to use suite.Suite
// type AuthenticationServiceTestSuite struct {
// 	suite.Suite
// 	controller            *gomock.Controller
// 	mockRepo              *repositoryMock.MockUserRepositoryer
// 	mockEmail             *serviceMock.MockEmailServicer
// 	mockJWTSigner  *jwtSignerMock.MockJWTSignerer
// 	authenticationService AuthenticationServicer
// }

// func (suite *AuthenticationServiceTestSuite) SetupTest() {
// 	suite.controller = gomock.NewController(suite.T())
// 	suite.mockRepo = repositoryMock.NewMockUserRepositoryer(suite.controller)
// 	suite.mockEmail = serviceMock.NewMockEmailServicer(suite.controller)
// 	suite.mockJWTSigner = serviceMock.NewMockJWTAthenticatorer(suite.controller)
// 	suite.authenticationService = NewAuthenticationService(suite.mockEmail, suite.mockRepo, suite.mockJWTSigner)
// }

// func (suite *AuthenticationServiceTestSuite) TearDownTest() {
// 	suite.controller.Finish()
// }

// func TestAuthenticationServiceTestSuite(t *testing.T) {
// 	suite.Run(t, new(AuthenticationServiceTestSuite))
// }

// type TestCase struct {
// 	name     string
// 	email    string
// 	password string
// 	err      error
// 	setup    func()
// }

// func (suite *AuthenticationServiceTestSuite) TestRegister() {
// 	testCases := []TestCase{
// 		{
// 			name:  "Register_Success",
// 			email: testEmail,
// 			setup: func() {
// 				suite.mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, nil)
// 				suite.mockUserRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
// 				suite.mockEmail.EXPECT().SendVerificationMail(gomock.Any(), testEmail, testFirstName, gomock.Any()).Return(nil)
// 			},
// 		},
// 		{
// 			name:  "Register_Email_Uniqueness",
// 			email: testEmail,
// 			setup: func() {
// 				suite.mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(&model.User{}, nil)
// 			},
// 			err: &model.EmailInUseError{Email: testEmail},
// 		},
// 		{
// 			name:  "Register_Invalid_Email",
// 			email: invalidEmail,
// 			setup: func() {
// 				suite.mockUserRepo.EXPECT().GetByEmail(gomock.Any(), invalidEmail).Return(nil, nil)
// 			},
// 			err: errors.New("Key: 'User.Email' Error:Field validation for 'Email' failed on the 'email' tag"),
// 		},
// 	}

// 	for _, tc := range testCases {
// 		suite.Run(tc.name, func() {
// 			tc.setup()
// 			err := suite.authenticationService.Register(context.Background(), tc.email, testPassword, testFirstName, testLastName, &testDateOfBirth)
// 			if tc.err != nil {
// 				suite.Assert().Error(err)
// 				suite.Assert().Equal(tc.err.Error(), err.Error())
// 			} else {
// 				suite.Assert().NoError(err)
// 			}
// 		})
// 	}
// }

func createAuthenticationService(controller *gomock.Controller) (
	*repositoryMock.MockUserRepositoryer,
	*repositoryMock.MockTokenRepositoryer,
	serviceMock.MockEmailServicer,
	jwtSignerMock.MockJWTSignerer,
	AuthenticationServicer,
) {
	mockUserRepo := repositoryMock.NewMockUserRepositoryer(controller)
	mockTokenRepo := repositoryMock.NewMockTokenRepositoryer(controller)
	mockEmail := serviceMock.NewMockEmailServicer(controller)
	mockJWTSigner := jwtSignerMock.NewMockJWTSignerer(controller)
	authenticationService := NewAuthenticationService(
		mockEmail,
		mockUserRepo,
		mockTokenRepo,
		mockJWTSigner,
	)

	return mockUserRepo, mockTokenRepo, *mockEmail, *mockJWTSigner, authenticationService
}

func TestAuthenticationService(test *testing.T) {
	// Register
	test.Run("Register_Success", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()
		mockUserRepo,
			mockTokenRepo,
			mockEmail,
			_,
			authenticationService := createAuthenticationService(controller)

		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, nil)
		mockUserRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(primitive.NewObjectID(), nil)
		mockTokenRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		mockEmail.EXPECT().SendVerificationMail(gomock.Any(), testEmail, testFirstName, gomock.Any()).Return(nil)

		// Test successful registration
		err := authenticationService.Register(
			context.Background(),
			testEmail,
			testPassword,
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)
		assert.NoError(test, err)
	})
	test.Run("Register_Email_Uniqueness", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockUserRepo,
			_,
			_,
			_,
			authenticationService := createAuthenticationService(controller)

		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(&model.User{}, nil)

		err := authenticationService.Register(
			context.Background(),
			testEmail,
			testPassword,
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)

		assert.Error(test, err)
		assert.Equal(test, (&model.EmailInUseError{Email: testEmail}).Error(), err.Error())
	})
	test.Run("Register_Invalid_Email", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()
		mockUserRepo,
			_,
			_,
			_,
			authenticationService := createAuthenticationService(controller)
		invalidEmail := "invalid-email"

		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), invalidEmail).Return(nil, nil)

		err := authenticationService.Register(
			context.Background(),
			invalidEmail,
			testPassword,
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)

		assert.Error(test, err)
		var validationErrs validator.ValidationErrors
		assert.ErrorAs(test, err, &validationErrs)
		assert.Contains(test, err.Error(), "Email")
	})
	test.Run("Register_Invalid_DOB", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockUserRepo,
			_,
			_,
			_,
			authenticationService := createAuthenticationService(controller)
		invalidDateOfBirth := time.Time{}

		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, nil)

		err := authenticationService.Register(
			context.Background(),
			testEmail,
			testPassword,
			testFirstName,
			testLastName,
			&invalidDateOfBirth,
		)

		assert.Error(test, err)
		var validationErrs validator.ValidationErrors
		assert.ErrorAs(test, err, &validationErrs)
		assert.Contains(test, err.Error(), "DateOfBirth")
	})
	test.Run("Register_Password_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockUserRepo,
			_,
			_,
			_,
			authenticationService := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, nil)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)
		// Test successful registration
		error := authenticationService.Register(
			ctx,
			testEmail,
			"testPassword",
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)
		assert.Error(test, error)
		assert.IsType(test, &NoComplexPasswordError{}, error)
		assert.Equal(test, "Password does not meet complexity requirements", error.Error())
	})

	test.Run("Register_Fail_Parsing_Inserted_ID_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockUserRepo,
			_,
			_,
			_,
			authenticationService := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, nil)
		mockUserRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil, nil)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)
		// Test successful registration
		err := authenticationService.Register(
			ctx,
			testEmail,
			testPassword,
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)
		assert.Error(test, err)
		assert.Equal(test, "InsertedID is not of type primitive.ObjectID: <nil>", err.Error())
	})

	test.Run("Register_Inserting_Verifiction_Token", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()
		mockedError := errors.New("Test error")

		mockUserRepo,
			mockTokenRepository,
			_,
			_,
			authenticationService := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, nil)
		mockUserRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(primitive.NewObjectID(), nil)
		mockTokenRepository.EXPECT().Create(gomock.Any(), gomock.Any()).Return(mockedError)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)
		// Test successful registration
		error := authenticationService.Register(
			ctx,
			testEmail,
			testPassword,
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)
		assert.Error(test, error)
		assert.Equal(test, "Error inserting verification token in DB: Test error", error.Error())
	})
	test.Run("Register_Send_email_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()
		mockedError := errors.New("Test error")

		mockUserRepo,
			mockTokenRepository,
			mockEmail,
			_,
			authenticationService := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, nil)
		mockUserRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(primitive.NewObjectID(), nil)
		mockTokenRepository.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		mockEmail.EXPECT().SendVerificationMail(
			gomock.Any(),
			testEmail,
			testFirstName,
			gomock.Any(),
		).Return(mockedError)
		logMock.EXPECT().Error(mockedError, "Error sending verification email")

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)
		// Test successful registration
		error := authenticationService.Register(
			ctx,
			testEmail,
			testPassword,
			testFirstName,
			testLastName,
			&testDateOfBirth,
		)
		assert.Error(test, error)
		assert.IsType(test, &SendEmailError{}, error)
		assert.Equal(test, "Error sending verification email", error.Error())
	})

	// Verify
	test.Run("Verify_Verify_Success", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockUserRepo,
			mockTokenRepo,
			_,
			_,
			authenticationService := createAuthenticationService(controller)

		testUser := newUser()
		testToken := newToken()

		mockTokenRepo.EXPECT().GetByToken(gomock.Any(), testToken.Token).Return(testToken, nil)
		mockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)
		mockUserRepo.EXPECT().Update(gomock.Any(), testUser).Return(nil)
		mockTokenRepo.EXPECT().Remove(gomock.Any(), testToken.Token).Return(nil)

		// Test successful verification
		err := authenticationService.VerifyEmail(context.Background(), testToken.Token)

		assert.NoError(test, err)
		assert.Equal(test, model.AccountStatusVerified, testUser.AccountStatus)
	})
	test.Run("Verify_Token_expired_error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		_,
			mockTokenRepo,
			_,
			_,
			authenticationService := createAuthenticationService(controller)

		expiredToken := newToken()
		expiredToken.ExpiresAt = time.Now().Add(-1 * time.Second)

		mockTokenRepo.EXPECT().GetByToken(gomock.Any(), expiredToken.Token).Return(expiredToken, nil)

		err := authenticationService.VerifyEmail(context.Background(), expiredToken.Token)

		assert.NotNil(test, err)
		assert.Error(test, err)
		assert.IsType(test, &Error{}, err)
		assert.Contains(test, err.Error(), "Verification token expired")

	})
	test.Run("Verify_Returns_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		_,
			mockTokenRepo,
			_,
			_,
			authenticationService := createAuthenticationService(controller)

		testToken := newToken()
		mockedError := errors.New("Test error")

		mockTokenRepo.EXPECT().GetByToken(gomock.Any(), testToken.Token).Return(nil, mockedError)

		// Test Verify
		resultError := authenticationService.VerifyEmail(context.Background(), testToken.Token)

		assert.Error(test, resultError)
		assert.Equal(test, "Invalid verification token", resultError.Error())
	})
	test.Run("Verify_Token_Wrong_Type_Of_Token_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		_,
			mockTokenRepo,
			_,
			_,
			authenticationService := createAuthenticationService(controller)

		testToken := newToken()
		testToken.Type = model.RefreshTokenType

		mockTokenRepo.EXPECT().GetByToken(gomock.Any(), testToken.Token).Return(testToken, nil)

		// Test Verify
		resultError := authenticationService.VerifyEmail(context.Background(), testToken.Token)

		assert.Error(test, resultError)
		assert.NotNil(test, resultError)
		assert.Equal(test, "Wrong type of token", resultError.Error())
	})
	test.Run("Verify_Get_User_By_ID_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockUserRepo,
			mockTokenRepo,
			_,
			_,
			authenticationService := createAuthenticationService(controller)

		testToken := newToken()
		mockError := errors.New("test-error")

		mockTokenRepo.EXPECT().GetByToken(gomock.Any(), testToken.Token).Return(testToken, nil)
		mockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(nil, mockError)

		// Test Verify
		resultError := authenticationService.VerifyEmail(context.Background(), testToken.Token)

		assert.Error(test, resultError)
		assert.NotNil(test, resultError)
		assert.Equal(test, "Error getting user by ID: test-error", resultError.Error())
	})
	test.Run("Verify_Get_User_Already_Verified_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockUserRepo,
			mockTokenRepo,
			_,
			_,
			authenticationService := createAuthenticationService(controller)

		testToken := newToken()
		testUser := newUser()
		testUser.AccountStatus = model.AccountStatusVerified

		mockTokenRepo.EXPECT().GetByToken(gomock.Any(), testToken.Token).Return(testToken, nil)
		mockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)

		// Test Verify
		resultError := authenticationService.VerifyEmail(context.Background(), testToken.Token)

		assert.Error(test, resultError)
		assert.IsType(test, &Error{}, resultError)
		assert.Equal(test, "Email already verified", resultError.Error())
	})
	test.Run("Verify_Update_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockUserRepo,
			mockTokenRepo,
			_,
			_,
			authenticationService := createAuthenticationService(controller)

		testToken := newToken()
		testUser := newUser()
		mockError := errors.New("update error")

		mockTokenRepo.EXPECT().GetByToken(gomock.Any(), testToken.Token).Return(testToken, nil)
		mockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)
		mockUserRepo.EXPECT().Update(gomock.Any(), testUser).Return(mockError)

		// Act
		resultError := authenticationService.VerifyEmail(context.Background(), testToken.Token)

		// Assert
		assert.Error(test, resultError)
		assert.Equal(test, "Error updating user: update error", resultError.Error())
	})

	test.Run("Verify_Update_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockUserRepo,
			mockTokenRepo,
			_,
			_,
			authenticationService := createAuthenticationService(controller)

		testToken := newToken()
		testUser := newUser()
		mockError := errors.New("update error")

		mockTokenRepo.EXPECT().GetByToken(gomock.Any(), testToken.Token).Return(testToken, nil)
		mockUserRepo.EXPECT().GetByUserID(gomock.Any(), testToken.UserID).Return(testUser, nil)
		mockUserRepo.EXPECT().Update(gomock.Any(), testUser).Return(nil)
		mockTokenRepo.EXPECT().Remove(gomock.Any(), testToken.Token).Return(mockError)

		// Act
		resultError := authenticationService.VerifyEmail(context.Background(), testToken.Token)

		// Assert
		assert.Error(test, resultError)
		assert.Equal(test, "Error removing token: update error", resultError.Error())
	})

	// Authenticate
	test.Run("Authenticate_GetByEmail_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockUserRepo,
			_,
			_,
			_,
			authenticationService := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		email := "test@example.com"
		errorMessage := "Database error"
		errorExample := errors.New(errorMessage)

		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), email).Return(nil, errorExample)
		logMock.EXPECT().Error(errorExample, "Error getting user by email")

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		// Test Authenticate
		user, err := authenticationService.Authenticate(ctx, email, "password")

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error getting user by email", err.Error())
		assert.Nil(test, user)
	})
	test.Run("Authenticate_User_Not_Found", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockUserRepo,
			_,
			_,
			_,
			authenticationService := createAuthenticationService(controller)

		email := "test@example.com"
		password := "password"

		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), email).Return(nil, nil)

		// Test Authenticate
		user, err := authenticationService.Authenticate(context.Background(), email, password)

		assert.Error(test, err)
		assert.Equal(test, "Wrong Email", err.Error())
		assert.Nil(test, user)
	})
	test.Run("Authenticate_Invalid_Password", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockUserRepo,
			_,
			_,
			_,
			authenticationService := createAuthenticationService(controller)

		email := "test@example.com"

		user := newUser()
		invalidPassword := "invalidpassword"

		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), email).Return(user, nil)

		// Test Authenticate
		resultUser, resultError := authenticationService.Authenticate(context.Background(), email, invalidPassword)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, resultUser)
		assert.Equal(test, "Wrong Password", resultError.Error())
	})
	test.Run("Authenticate_AuthToken_Signing_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockUserRepo,
			_,
			_,
			mockJWTSigner,
			authenticationService := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		user := newUser()
		user.PasswordHash = "$2a$10$b4R.rxNHsELRW/JaqI1kS.CXO.xVamz.rwFXxchWD2pdKhKzZp94u"
		user.PasswordSalt = "7jQQnlalvK1E0iDzugF18ewa1Auf7R71Dr6OWnJbZbI="
		error := errors.New("some error")

		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(user, nil)
		mockJWTSigner.EXPECT().SignToken(
			gomock.Any(),
			gomock.Any(),
		).Return(nil, error)
		logMock.EXPECT().Error(error, "Error creating jwt token")

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		// Test Authenticate
		resultUser, resultError := authenticationService.Authenticate(
			ctx,
			testEmail,
			testPassword,
		)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, resultUser)
		assert.Equal(test, "Error creating authentication token", resultError.Error())
	})
	test.Run("Authenticate_Update_User_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockUserRepo,
			_,
			_,
			mockJWTSigner,
			authenticationService := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		user := newUser()
		user.PasswordHash = "$2a$10$b4R.rxNHsELRW/JaqI1kS.CXO.xVamz.rwFXxchWD2pdKhKzZp94u"
		user.PasswordSalt = "7jQQnlalvK1E0iDzugF18ewa1Auf7R71Dr6OWnJbZbI="
		exampleError := errors.New("some error")

		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(user, nil)
		mockJWTSigner.EXPECT().SignToken(gomock.Any(), gomock.Any()).Return(&token, nil)
		mockJWTSigner.EXPECT().SignToken(gomock.Any(), gomock.Any()).Return(&refreshToken, nil)
		mockUserRepo.EXPECT().Update(gomock.Any(), user).Return(exampleError)
		logMock.EXPECT().Error(exampleError, "Error updating user")

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		// Act
		resultUser, resultError := authenticationService.Authenticate(ctx, testEmail, testPassword)

		// Assert
		assert.Error(test, resultError)
		assert.Nil(test, resultUser)
		assert.Equal(test, "Error updating user", resultError.Error())
	})
	test.Run("Authenticate_Authenticate_Success", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockUserRepo,
			_,
			_,
			mockJWTSigner,
			authenticationService := createAuthenticationService(controller)

		user := newUser()
		user.PasswordHash = "$2a$10$b4R.rxNHsELRW/JaqI1kS.CXO.xVamz.rwFXxchWD2pdKhKzZp94u"
		user.PasswordSalt = "7jQQnlalvK1E0iDzugF18ewa1Auf7R71Dr6OWnJbZbI="

		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(user, nil)
		mockJWTSigner.EXPECT().SignToken(gomock.Any(), gomock.Any()).Return(&token, nil)
		mockJWTSigner.EXPECT().SignToken(gomock.Any(), gomock.Any()).Return(&refreshToken, nil)
		mockUserRepo.EXPECT().Update(gomock.Any(), user).Return(nil)

		// Act
		resultUser, resultError := authenticationService.Authenticate(context.Background(), testEmail, testPassword)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, resultUser)
		assert.Equal(test, testEmail, resultUser.UserEmail)
	})

	// VerifyTokenAndDecodeEmail
	test.Run("VerifyTokenAndDecodeEmail_VerifyToken_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		_, _, _, mockJWTSigner, authenticationService := createAuthenticationService(controller)

		token := "invalid-token"
		mockedError := errors.New("Token verification failed")

		mockJWTSigner.EXPECT().VerifyToken(token).Return(nil, mockedError)

		// Act
		email, err := authenticationService.VerifyTokenAndDecodeEmail(context.Background(), token)

		// Assert
		assert.Error(test, err)
		assert.Nil(test, email)
		assert.Equal(test, "Error verifying token: Token verification failed", err.Error())
	})

	test.Run("VerifyTokenAndDecodeEmail_GetEmailFromToken_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		_, _, _, mockJWTSigner, authenticationService := createAuthenticationService(controller)

		token := "valid-token"
		mockedError := errors.New("Error decoding email")

		mockJWTSigner.EXPECT().VerifyToken(token).Return(&jwt.Token{}, nil)
		mockJWTSigner.EXPECT().GetEmailFromToken(gomock.Any()).Return(nil, mockedError)

		// Act
		email, err := authenticationService.VerifyTokenAndDecodeEmail(context.Background(), token)

		// Assert
		assert.Error(test, err)
		assert.Nil(test, email)
		assert.Equal(test, "Error getting email from token: Error decoding email", err.Error())
	})

	test.Run("VerifyTokenAndDecodeEmail_Success", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		_, _, _, mockJWTSigner, authenticationService := createAuthenticationService(controller)

		exampleEmail := "example@email.com"
		token := "valid-token"
		jwtToken := jwt.Token{}
		mockJWTSigner.EXPECT().VerifyToken(token).Return(&jwtToken, nil)
		mockJWTSigner.EXPECT().GetEmailFromToken(&jwtToken).Return(&exampleEmail, nil)

		// Act
		email, err := authenticationService.VerifyTokenAndDecodeEmail(context.Background(), token)

		// Assert
		assert.NoError(test, err)
		assert.NotNil(test, email)
		assert.Equal(test, exampleEmail, *email)
	})

	// // ResendEmailVerification
	test.Run("ResendEmailVerification_GetByEmail_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockUserRepo,
			_,
			_,
			_,
			authenticationService := createAuthenticationService(controller)

		mockedError := errors.New("User repository error")

		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, mockedError)

		// Act
		err := authenticationService.ResendEmailVerification(context.Background(), testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error getting user by email: User repository error", err.Error())
	})

	test.Run("ResendEmailVerification_GetByEmail_NotFound", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockUserRepo,
			_,
			_,
			_,
			authenticationService := createAuthenticationService(controller)

		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(nil, nil)

		// Act
		err := authenticationService.ResendEmailVerification(context.Background(), testEmail)

		// Assert
		assert.Error(test, err)
		assert.IsType(test, &Error{}, err)
		assert.Contains(test, err.Error(), "Invalid email")
	})

	test.Run("ResendEmailVerification_GetByEmail_AlreadyVerified", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		user := newUser()
		user.AccountStatus = model.AccountStatusVerified

		mockUserRepo,
			_,
			_,
			_,
			authenticationService := createAuthenticationService(controller)

		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(user, nil)

		// Act
		err := authenticationService.ResendEmailVerification(context.Background(), testEmail)

		// Assert
		assert.Error(test, err)
		assert.IsType(test, &Error{}, err)
		assert.Contains(test, err.Error(), "Email already verified")
	})

	test.Run("ResendEmailVerification_UserUpdate_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockUserRepo,
			mockTokenRepo,
			_,
			_,
			authenticationService := createAuthenticationService(controller)

		testUser := newUser()
		mockedError := errors.New("Create error")

		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)
		mockTokenRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(mockedError)

		// Act
		err := authenticationService.ResendEmailVerification(context.Background(), testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error inserting the verification token in db: Create error", err.Error())
	})

	test.Run("ResendEmailVerification_SendEmail_Error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockUserRepo,
			mockTokenRepo,
			mockEmail,
			_,
			authenticationService := createAuthenticationService(controller)

		testUser := newUser()
		mockedError := errors.New("Email service error")

		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)
		mockTokenRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		mockEmail.EXPECT().SendVerificationMail(
			context.Background(),
			testEmail,
			testUser.FirstName,
			gomock.Any(),
		).Return(mockedError)

		// Act
		err := authenticationService.ResendEmailVerification(context.Background(), testEmail)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error sending verification email: Email service error", err.Error())
	})

	test.Run("ResendEmailVerification_Success", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockUserRepo,
			mockTokenRepo,
			mockEmail,
			_,
			authenticationService := createAuthenticationService(controller)

		testUser := newUser()

		mockUserRepo.EXPECT().GetByEmail(gomock.Any(), testEmail).Return(testUser, nil)
		mockTokenRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		mockEmail.EXPECT().SendVerificationMail(
			context.Background(),
			testEmail,
			testUser.FirstName,
			gomock.Any(),
		).Return(nil)

		// Act
		err := authenticationService.ResendEmailVerification(context.Background(), testEmail)

		// Assert
		assert.NoError(test, err)
	})

	// RefreshToken
	test.Run("RefreshToken_VerifyToken_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		_,
			_,
			_,
			mockJWTAuthenticator,
			authenticationService := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		token := "test_token"
		errorMessage := "Database error"
		errorExample := errors.New(errorMessage)

		mockJWTAuthenticator.EXPECT().VerifyToken(gomock.Any()).Return(nil, errorExample)
		logMock.EXPECT().Error(errorExample, "Error verifying refresh token")

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		// Test RefreshToken
		user, err := authenticationService.RefreshToken(ctx, token)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Invalid or expired refresh token", err.Error())
		assert.Nil(test, user)
	})

	test.Run("RefreshToken_GetByEmail_error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		_,
			_,
			_,
			mockJWTAuthenticator,
			authenticationService := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		token := "test_token"
		errorMessage := "Database error"
		errorExample := errors.New(errorMessage)

		mockJWTAuthenticator.EXPECT().VerifyToken(token).Return(&jwt.Token{}, nil)
		mockJWTAuthenticator.EXPECT().GetEmailFromToken(gomock.Any()).Return(nil, errorExample)
		logMock.EXPECT().Error(errorExample, "Error getting email from token")

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		// Test RefreshToken
		user, err := authenticationService.RefreshToken(ctx, token)

		// Assert
		assert.Error(test, err)
		assert.Equal(test, "Error getting email from token", err.Error())
		assert.Nil(test, user)
	})
	test.Run("RefreshToken_User_Not_Found", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepository,
			_,
			_,
			mockJWTAuthenticator,
			authenticationService := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		token := "test_token"
		jwtToken := &jwt.Token{}
		email := "email@example.com"
		errorMessage := "Database error"
		errorExample := errors.New(errorMessage)

		mockJWTAuthenticator.EXPECT().VerifyToken(token).Return(jwtToken, nil)
		mockJWTAuthenticator.EXPECT().GetEmailFromToken(jwtToken).Return(&email, nil)
		mockRepository.EXPECT().GetByEmail(gomock.Any(), email).Return(nil, errorExample)
		logMock.EXPECT().Error(errorExample, "Error getting user by email")

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		// Test RefreshToken
		user, err := authenticationService.RefreshToken(ctx, token)

		assert.Error(test, err)
		assert.Equal(test, "Error getting user by email", err.Error())
		assert.Nil(test, user)
	})

	test.Run("RefreshToken_Token_Not_Listed", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepository,
			_,
			_,
			mockJWTSigner,
			authenticationService := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		token := "test_token"
		jwtToken := &jwt.Token{}
		email := "email@example.com"
		user := newUser()

		mockJWTSigner.EXPECT().VerifyToken(token).Return(jwtToken, nil)
		mockJWTSigner.EXPECT().GetEmailFromToken(jwtToken).Return(&email, nil)
		mockRepository.EXPECT().GetByEmail(gomock.Any(), email).Return(user, nil)
		mockJWTSigner.EXPECT().SignToken(gomock.Any(), gomock.Any()).Return(&token, nil)
		mockJWTSigner.EXPECT().SignToken(gomock.Any(), gomock.Any()).Return(&refreshToken, nil)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		// Test RefreshToken
		resultUser, resultError := authenticationService.RefreshToken(ctx, token)

		// Assert
		assert.Error(test, resultError)
		assert.Equal(test, resultError.Error(), "Refresh token is not listed")
		assert.Nil(test, resultUser)
	})

	test.Run("RefreshToken_Update_User_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepository,
			_,
			_,
			mockJWTSigner,
			authenticationService := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		jwtToken := &jwt.Token{}
		email := "email@example.com"
		user := newUser()
		exampleError := errors.New("new error")

		mockJWTSigner.EXPECT().VerifyToken(refreshToken).Return(jwtToken, nil)
		mockJWTSigner.EXPECT().GetEmailFromToken(jwtToken).Return(&email, nil)
		mockRepository.EXPECT().GetByEmail(gomock.Any(), email).Return(user, nil)
		mockJWTSigner.EXPECT().SignToken(gomock.Any(), gomock.Any()).Return(&refreshToken, nil)
		mockJWTSigner.EXPECT().SignToken(gomock.Any(), gomock.Any()).Return(&refreshToken, nil)
		mockRepository.EXPECT().Update(gomock.Any(), user).Return(exampleError)
		logMock.EXPECT().Error(exampleError, "Error updating user")

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		// Test RefreshToken
		resultUser, resultError := authenticationService.RefreshToken(ctx, refreshToken)

		// Assert
		assert.Error(test, resultError)
		assert.Equal(test, resultError.Error(), "Error updating user")
		assert.Nil(test, resultUser)
	})

	test.Run("RefreshToken_Success", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		mockRepository,
			_,
			_,
			mockJWTSigner,
			authenticationService := createAuthenticationService(controller)
		logMock := loggerMock.NewMockLoggerer(controller)

		token := "test_token"
		jwtToken := &jwt.Token{}
		email := "email@example.com"
		user := newUser()

		mockJWTSigner.EXPECT().VerifyToken(refreshToken).Return(jwtToken, nil)
		mockJWTSigner.EXPECT().GetEmailFromToken(jwtToken).Return(&email, nil)
		mockRepository.EXPECT().GetByEmail(gomock.Any(), email).Return(user, nil)
		mockJWTSigner.EXPECT().SignToken(gomock.Any(), gomock.Any()).Return(&token, nil)
		mockJWTSigner.EXPECT().SignToken(gomock.Any(), gomock.Any()).Return(&refreshToken, nil)
		mockRepository.EXPECT().Update(gomock.Any(), user).Return(nil)

		ctx := context.WithValue(context.Background(), log.LoggerKey, logMock)

		// Test RefreshToken
		resultUser, resultError := authenticationService.RefreshToken(ctx, refreshToken)

		// Assert
		assert.NoError(test, resultError)
		assert.NotNil(test, resultUser)
		assert.Equal(test, testEmail, user.Email)
	})
}

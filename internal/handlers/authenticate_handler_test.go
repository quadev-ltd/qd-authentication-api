package handlers

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"qd_authentication_api/internal/model"
	"qd_authentication_api/internal/pb"
	"qd_authentication_api/internal/service/mock"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAuthenticateHandler(t *testing.T) {
	t.Run("Invalid Request Payload", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(ctrl)

		// Create a request with invalid Protobuff payload
		request, err := http.NewRequest(http.MethodPost, "/authenticate", bytes.NewReader([]byte("invalid-data")))
		assert.NoError(t, err)

		recorder := httptest.NewRecorder()

		handler := AuthenticateHandler(authenticationServiceMock)

		router := http.NewServeMux()
		router.HandleFunc("/authenticate", handler)

		router.ServeHTTP(recorder, request)

		// Check response status code and error message
		assert.Equal(t, http.StatusBadRequest, recorder.Code)
		// TODO create a reusable error with an identifier and an internal error message interface
		assert.Contains(t, recorder.Body.String(), "Invalid request payload")
	})

	t.Run("Authentication Error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(ctrl)

		requestBody := &pb.AuthenticateRequest{
			Email:    "test@example.com",
			Password: "password",
		}

		// Simulate an authentication error
		expectedError := &model.WrongEmailOrPassword{FieldName: "Email"}
		authenticationServiceMock.EXPECT().Authenticate(requestBody.Email, requestBody.Password).Return(nil, expectedError)

		// Create a request with valid Protobuff payload
		bodyBytes, requestCreationError := proto.Marshal(requestBody)
		assert.NoError(t, requestCreationError)

		request, requestCreationError := http.NewRequest(http.MethodPost, "/authenticate", bytes.NewBuffer(bodyBytes))
		assert.NoError(t, requestCreationError)

		recorder := httptest.NewRecorder()

		handler := AuthenticateHandler(authenticationServiceMock)

		router := http.NewServeMux()
		router.HandleFunc("/authenticate", handler)

		router.ServeHTTP(recorder, request)

		// Check response status code and error message
		assert.Equal(t, http.StatusUnauthorized, recorder.Code)
		assert.Contains(t, recorder.Body.String(), "Invalid email or password")
	})

	t.Run("Authentication Error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(ctrl)

		requestBody := &pb.AuthenticateRequest{
			Email:    "test@example.com",
			Password: "password",
		}

		expectedError := errors.New("some error")
		authenticationServiceMock.EXPECT().Authenticate(requestBody.Email, requestBody.Password).Return(nil, expectedError)

		// Create a request with valid Protobuff payload
		bodyBytes, requestCreationError := proto.Marshal(requestBody)
		assert.NoError(t, requestCreationError)

		request, requestCreationError := http.NewRequest(http.MethodPost, "/authenticate", bytes.NewBuffer(bodyBytes))
		assert.NoError(t, requestCreationError)

		recorder := httptest.NewRecorder()

		handler := AuthenticateHandler(authenticationServiceMock)

		router := http.NewServeMux()
		router.HandleFunc("/authenticate", handler)

		router.ServeHTTP(recorder, request)

		// Check response status code and error message
		assert.Equal(t, http.StatusInternalServerError, recorder.Code)
		assert.Contains(t, recorder.Body.String(), "Internal server error")
	})

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(ctrl)

		requestBody := &pb.AuthenticateRequest{
			Email:    "test@example.com",
			Password: "password",
		}

		// Simulate a successful authentication
		authTokens := &model.AuthTokensResponse{
			AuthToken:          "sample-auth-token",
			AuthTokenExpiry:    time.Now().Add(15 * time.Minute),
			RefreshToken:       "sample-refresh-token",
			RefreshTokenExpiry: time.Now().Add(7 * 24 * time.Hour),
			UserEmail:          requestBody.Email,
		}
		expectedAuthTokens := &pb.AuthenticateResponse{
			AuthToken:          "sample-auth-token",
			AuthTokenExpiry:    timestamppb.New(time.Now().Add(15 * time.Minute)),
			RefreshToken:       "sample-refresh-token",
			RefreshTokenExpiry: timestamppb.New(time.Now().Add(7 * 24 * time.Hour)),
			UserEmail:          requestBody.Email,
		}
		authenticationServiceMock.EXPECT().Authenticate(requestBody.Email, requestBody.Password).Return(authTokens, nil)

		// Create a request with valid Protobuff payload
		bodyBytes, err := proto.Marshal(requestBody)
		assert.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, "/authenticate", bytes.NewBuffer(bodyBytes))
		assert.NoError(t, err)

		recorder := httptest.NewRecorder()

		handler := AuthenticateHandler(authenticationServiceMock)

		router := http.NewServeMux()
		router.HandleFunc("/authenticate", handler)

		router.ServeHTTP(recorder, req)

		// Check response status code and AuthTokensResponse
		assert.Equal(t, http.StatusOK, recorder.Code)

		// Decode the authenticationResponse to protobuff and assert its contents
		var authenticationResponse pb.AuthenticateResponse
		err = proto.Unmarshal(recorder.Body.Bytes(), &authenticationResponse)
		assert.NoError(t, err)

		// Define a tolerance for time comparison
		timeTolerance := time.Second

		// Compare time values with tolerance
		assert.WithinDuration(t, expectedAuthTokens.AuthTokenExpiry.AsTime(), authenticationResponse.AuthTokenExpiry.AsTime(), timeTolerance)
		assert.WithinDuration(t, expectedAuthTokens.RefreshTokenExpiry.AsTime(), authenticationResponse.RefreshTokenExpiry.AsTime(), timeTolerance)
		assert.Equal(t, expectedAuthTokens.AuthToken, authenticationResponse.AuthToken)
		assert.Equal(t, expectedAuthTokens.RefreshToken, authenticationResponse.RefreshToken)
		assert.Equal(t, expectedAuthTokens.UserEmail, authenticationResponse.UserEmail)
	})
}

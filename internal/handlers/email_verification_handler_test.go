package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"qd_authentication_api/internal/service/mock"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestEmailVerificationHandler(test *testing.T) {
	test.Run("Success", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)
		verificationToken := "token"

		authenticationServiceMock.EXPECT().Verify(verificationToken).Return(nil)

		req, err := http.NewRequest(http.MethodGet, "/verify/"+verificationToken, nil)
		assert.NoError(test, err)

		recorder := httptest.NewRecorder()

		handler := EmailVerificationHandler(authenticationServiceMock)

		router := mux.NewRouter()
		router.HandleFunc("/verify/{verification_token}", handler)

		router.ServeHTTP(recorder, req)

		assert.Equal(test, http.StatusOK, recorder.Code)
	})
	test.Run("Verify error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)
		verificationToken := "token"
		expectedError := errors.New("verification error")

		authenticationServiceMock.EXPECT().Verify(verificationToken).Return(expectedError)

		req, err := http.NewRequest(http.MethodGet, "/verify/"+verificationToken, nil)
		assert.NoError(test, err)

		recorder := httptest.NewRecorder()

		handler := EmailVerificationHandler(authenticationServiceMock)

		router := mux.NewRouter()
		router.HandleFunc("/verify/{verification_token}", handler)

		router.ServeHTTP(recorder, req)

		assert.Equal(test, http.StatusInternalServerError, recorder.Code)
		assert.Contains(test, recorder.Body.String(), expectedError.Error())
	})
}

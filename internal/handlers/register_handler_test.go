package handlers

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"qd_authentication_api/internal/model"
	"qd_authentication_api/internal/service/mock"
	"qd_authentication_api/pb/gen/go/pb_authentication"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func testRegisterHandler_Success(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()

	authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)

	userPb := &pb_authentication.RegisterRequest{
		Email:       "test@example.com",
		Password:    "password",
		FirstName:   "First",
		LastName:    "Last",
		DateOfBirth: timestamppb.New(time.Now()),
	}

	userPbBytes, _ := proto.Marshal(userPb)

	authenticationServiceMock.EXPECT().Register(userPb.Email, userPb.Password, userPb.FirstName, userPb.LastName, gomock.Any()).Return(nil)

	request, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(userPbBytes))
	responseRecorder := httptest.NewRecorder()

	// Act
	RegisterHandler(authenticationServiceMock)(responseRecorder, request)

	// Assert
	assert.Equal(test, http.StatusOK, responseRecorder.Code)
}

// errorReader is an io.Reader that always returns an error.
type errorReader struct{}

const testError = "forced error"

func (er *errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New(testError)
}

func testRegisterHandler_ReadBodyError(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()

	authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)

	request, _ := http.NewRequest("POST", "/register", &errorReader{})
	responseRecorder := httptest.NewRecorder()

	// Act
	RegisterHandler(authenticationServiceMock)(responseRecorder, request)

	// Assert
	assert.Equal(test, http.StatusBadRequest, responseRecorder.Code)
	bodyBytes := responseRecorder.Body.Bytes()
	bodyString := string(bodyBytes)
	assert.Equal(test, fmt.Sprintf("Error trying to read request body: %s\n", testError), bodyString)
}

func testRegisterHandler_UnmarshalError(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()

	authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)

	invalidProtobuf := []byte("not a valid protobuf message")
	request, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(invalidProtobuf))
	responseRecorder := httptest.NewRecorder()

	// Act
	RegisterHandler(authenticationServiceMock)(responseRecorder, request)

	// Assert
	assert.Equal(test, http.StatusBadRequest, responseRecorder.Code)
	bodyBytes := responseRecorder.Body.Bytes()
	bodyString := string(bodyBytes)
	assert.Contains(test, bodyString, "cannot parse invalid wire-format data")
}

func testRegisterHandler_ValidationError(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()

	authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)

	userPb := &pb_authentication.RegisterRequest{
		Email:       "test@example.com",
		Password:    "password",
		FirstName:   "First",
		LastName:    "Last",
		DateOfBirth: timestamppb.New(time.Now()),
	}

	bodyBytes, _ := proto.Marshal(userPb)

	mockValidationError := validator.ValidationErrors{}
	authenticationServiceMock.EXPECT().Register(userPb.Email, userPb.Password, userPb.FirstName, userPb.LastName, gomock.Any()).Return(mockValidationError)

	request, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(bodyBytes))
	responseRecorder := httptest.NewRecorder()

	// Act
	RegisterHandler(authenticationServiceMock)(responseRecorder, request)

	// Assert
	assert.Equal(test, http.StatusBadRequest, responseRecorder.Code)
	bodyBytes = responseRecorder.Body.Bytes()
	bodyString := string(bodyBytes)
	assert.Equal(test, fmt.Sprintf("Register error: %s\n", mockValidationError.Error()), bodyString)
}

func testRegisterHandler_EmailInUseError(test *testing.T) {
	// Arrange
	controller := gomock.NewController(test)
	defer controller.Finish()

	authenticationServiceMock := mock.NewMockAuthenticationServicer(controller)

	userPb := &pb_authentication.RegisterRequest{
		Email:       "test@example.com",
		Password:    "password",
		FirstName:   "First",
		LastName:    "Last",
		DateOfBirth: timestamppb.New(time.Now()),
	}

	bodyBytes, _ := proto.Marshal(userPb)

	mockEmailInUseError := &model.EmailInUseError{Email: "test@example.com"}
	authenticationServiceMock.EXPECT().Register(userPb.Email, userPb.Password, userPb.FirstName, userPb.LastName, gomock.Any()).Return(mockEmailInUseError)

	request, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(bodyBytes))
	responseRecorder := httptest.NewRecorder()

	// Act
	RegisterHandler(authenticationServiceMock)(responseRecorder, request)

	// Assert
	assert.Equal(test, http.StatusBadRequest, responseRecorder.Code)
	bodyBytes = responseRecorder.Body.Bytes()
	bodyString := string(bodyBytes)
	assert.Equal(test, fmt.Sprintf("Register error: %s\n", mockEmailInUseError.Error()), bodyString)
}

func TestRegisterHandler(test *testing.T) {
	// Run all the test functions
	test.Run("Success", testRegisterHandler_Success)
	test.Run("Read Body Error", testRegisterHandler_ReadBodyError)
	test.Run("Unmarshal Error", testRegisterHandler_UnmarshalError)
	test.Run("Validation Error", testRegisterHandler_ValidationError)
	test.Run("Email In Use Error", testRegisterHandler_EmailInUseError)
}

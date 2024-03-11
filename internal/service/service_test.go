package service

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	repositoryMock "qd-authentication-api/internal/repository/mock"
	"qd-authentication-api/internal/service/mock"
)

func TestService(test *testing.T) {
	test.Run("Close_Client_No_Error", func(test *testing.T) {
		// Arrange
		controller := gomock.NewController(test)
		defer controller.Finish()

		authenticationServiceMock := mock.NewMockUserServicer(controller)
		repositoryMock := repositoryMock.NewMockRepositoryer(controller)

		service := &Service{
			authenticationService: authenticationServiceMock,
			repository:            repositoryMock,
		}

		repositoryMock.EXPECT().Close().Return(nil)

		err := service.Close()

		assert.NoError(test, err)
	})

	test.Run("Close_Client_Nil_Error", func(test *testing.T) {
		service := &Service{
			authenticationService: nil,
			repository:            nil,
		}

		err := service.Close()

		assert.Equal(test, "Service repository is nil", err.Error())
	})
}

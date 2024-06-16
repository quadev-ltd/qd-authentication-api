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

		userServiceMock := mock.NewMockUserServicer(controller)
		emailServiceMock := mock.NewMockEmailServicer(controller)
		repositoryMock := repositoryMock.NewMockRepositoryer(controller)

		service := &Manager{
			userService:  userServiceMock,
			emailService: emailServiceMock,
			repository:   repositoryMock,
		}

		emailServiceMock.EXPECT().Close().Return(nil)
		repositoryMock.EXPECT().Close().Return(nil)

		err := service.Close()

		assert.NoError(test, err)
	})

	test.Run("Close_Client_Nil_Repository_Error", func(test *testing.T) {
		service := &Manager{
			userService: nil,
			repository:  nil,
		}

		err := service.Close()

		assert.Equal(test, "Service repository is nil", err.Error())
	})

	test.Run("Close_Client_Nil_EmailService_Error", func(test *testing.T) {
		controller := gomock.NewController(test)
		defer controller.Finish()

		userServiceMock := mock.NewMockUserServicer(controller)
		repositoryMock := repositoryMock.NewMockRepositoryer(controller)

		service := &Manager{
			userService: userServiceMock,
			repository:  repositoryMock,
		}

		repositoryMock.EXPECT().Close().Return(nil)

		err := service.Close()

		assert.Equal(test, "Email service is nil", err.Error())
	})
}

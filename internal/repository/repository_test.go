package repository

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockClient struct {
	mock.Mock
}

func (m *MockClient) Connect(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockClient) Disconnect(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func TestRepository(test *testing.T) {
	test.Run("Close_Client_Nil_Error", func(test *testing.T) {
		repository := &Repository{
			client: nil,
		}

		err := repository.Close()

		assert.Equal(test, "Repository client is nil.", err.Error())
	})

	test.Run("Close_Success", func(test *testing.T) {
		client := new(MockClient)
		client.On("Disconnect", mock.Anything).Return(nil)

		repository := &Repository{
			client: client,
		}

		err := repository.Close()

		client.AssertCalled(test, "Disconnect", mock.Anything)
		assert.NoError(test, err)
	})
}

package mongo

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	repositoryTypes "qd-authentication-api/internal/repository"
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
		repository := &RepositoryStore{
			client: nil,
		}

		err := repository.Close()

		assert.Error(test, err)
		assert.Equal(test, "Repository client is nil", err.Error())
		assert.IsType(test, &repositoryTypes.Error{}, err)

	})

	test.Run("Close_Success", func(test *testing.T) {
		client := new(MockClient)
		client.On("Disconnect", mock.Anything).Return(nil)

		repository := &RepositoryStore{
			client: client,
		}

		err := repository.Close()

		client.AssertCalled(test, "Disconnect", mock.Anything)
		assert.NoError(test, err)
	})
}

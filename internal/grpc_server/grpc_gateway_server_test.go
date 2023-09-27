package grpc_server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockCancelFunc struct {
	mock.Mock
}

func (m *MockCancelFunc) Call() {
	m.Called()
}

func TestGRPCGatewayService(test *testing.T) {
	test.Run("Server_Cacel_Function_Is_Nil", func(test *testing.T) {
		service := &GRPCGatewayService{
			gatewayServerAddress: "localhost:1111",
			mux:                  nil,
			cancel:               nil,
		}

		err := service.Close()

		assert.Equal(test, "Function cancel is nil.", err.Error())
	})
}

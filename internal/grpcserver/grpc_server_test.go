package grpcserver

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockListener struct {
	mock.Mock
}

func (m *MockListener) Accept() (net.Conn, error) {
	args := m.Called()
	return args.Get(0).(net.Conn), args.Error(1)
}

func (m *MockListener) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockListener) Addr() net.Addr {
	args := m.Called()
	return args.Get(0).(net.Addr)
}

type MockGRPCServer struct {
	mock.Mock
}

func (m *MockGRPCServer) Serve(listener net.Listener) error {
	args := m.Called(listener)
	return args.Error(0)
}

func (m *MockGRPCServer) Stop() {
	m.Called()
}

func TestGRPCService(test *testing.T) {

	test.Run("Serve_Success", func(test *testing.T) {
		listener := new(MockListener)
		server := new(MockGRPCServer)
		server.On("Serve", listener).Return(nil)

		service := &GRPCService{
			grpcServer:   server,
			grpcListener: listener,
		}

		err := service.Serve()

		assert.Nil(test, err)

		server.AssertCalled(test, "Serve", listener)
	})

	test.Run("Close_Success", func(test *testing.T) {
		listener := new(MockListener)
		listener.On("Close").Return(nil)
		server := new(MockGRPCServer)
		server.On("Stop").Return(nil)

		service := &GRPCService{
			grpcServer:   server,
			grpcListener: listener,
		}

		err := service.Close()

		assert.Nil(test, err)

		listener.AssertCalled(test, "Close")
		server.AssertCalled(test, "Stop")
	})

	test.Run("Close_Listner_Nil_Error", func(test *testing.T) {
		listener := new(MockListener)
		listener.On("Close").Return(nil)

		service := &GRPCService{
			grpcServer:   nil,
			grpcListener: listener,
		}

		err := service.Close()

		listener.AssertCalled(test, "Close")
		assert.NoError(test, err)
	})

	test.Run("Close_Listner_Nil_Error", func(test *testing.T) {
		server := new(MockGRPCServer)
		server.On("Stop").Return(nil)

		service := &GRPCService{
			grpcServer:   server,
			grpcListener: nil,
		}

		err := service.Close()

		assert.Error(test, err)
		assert.Equal(test, "GRPC server or listener is nil", err.Error())
	})

	test.Run("Close_Listner_Nil_Error", func(test *testing.T) {
		service := &GRPCService{
			grpcServer:   nil,
			grpcListener: nil,
		}

		err := service.Close()

		assert.Error(test, err)
		assert.Equal(test, "GRPC server or listener is nil", err.Error())
	})
}

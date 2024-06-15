// Code generated by MockGen. DO NOT EDIT.
// Source: auth.go

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"

	auth "firebase.google.com/go/auth"
	gomock "github.com/golang/mock/gomock"
)

// MockAuthServicer is a mock of AuthServicer interface.
type MockAuthServicer struct {
	ctrl     *gomock.Controller
	recorder *MockAuthServicerMockRecorder
}

// MockAuthServicerMockRecorder is the mock recorder for MockAuthServicer.
type MockAuthServicerMockRecorder struct {
	mock *MockAuthServicer
}

// NewMockAuthServicer creates a new mock instance.
func NewMockAuthServicer(ctrl *gomock.Controller) *MockAuthServicer {
	mock := &MockAuthServicer{ctrl: ctrl}
	mock.recorder = &MockAuthServicerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthServicer) EXPECT() *MockAuthServicerMockRecorder {
	return m.recorder
}

// VerifyIDToken mocks base method.
func (m *MockAuthServicer) VerifyIDToken(ctx context.Context, idToken string) (*auth.Token, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyIDToken", ctx, idToken)
	ret0, _ := ret[0].(*auth.Token)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyIDToken indicates an expected call of VerifyIDToken.
func (mr *MockAuthServicerMockRecorder) VerifyIDToken(ctx, idToken interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyIDToken", reflect.TypeOf((*MockAuthServicer)(nil).VerifyIDToken), ctx, idToken)
}
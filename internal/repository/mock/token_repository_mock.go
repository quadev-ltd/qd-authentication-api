// Code generated by MockGen. DO NOT EDIT.
// Source: token_repository.go

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	model "qd-authentication-api/internal/model"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockTokenRepositoryer is a mock of TokenRepositoryer interface.
type MockTokenRepositoryer struct {
	ctrl     *gomock.Controller
	recorder *MockTokenRepositoryerMockRecorder
}

// MockTokenRepositoryerMockRecorder is the mock recorder for MockTokenRepositoryer.
type MockTokenRepositoryerMockRecorder struct {
	mock *MockTokenRepositoryer
}

// NewMockTokenRepositoryer creates a new mock instance.
func NewMockTokenRepositoryer(ctrl *gomock.Controller) *MockTokenRepositoryer {
	mock := &MockTokenRepositoryer{ctrl: ctrl}
	mock.recorder = &MockTokenRepositoryerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTokenRepositoryer) EXPECT() *MockTokenRepositoryerMockRecorder {
	return m.recorder
}

// GetByToken mocks base method.
func (m *MockTokenRepositoryer) GetByToken(ctx context.Context, token string) (*model.Token, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByToken", ctx, token)
	ret0, _ := ret[0].(*model.Token)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByToken indicates an expected call of GetByToken.
func (mr *MockTokenRepositoryerMockRecorder) GetByToken(ctx, token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByToken", reflect.TypeOf((*MockTokenRepositoryer)(nil).GetByToken), ctx, token)
}

// InsertToken mocks base method.
func (m *MockTokenRepositoryer) InsertToken(ctx context.Context, token *model.Token) (interface{}, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InsertToken", ctx, token)
	ret0, _ := ret[0].(interface{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InsertToken indicates an expected call of InsertToken.
func (mr *MockTokenRepositoryerMockRecorder) InsertToken(ctx, token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertToken", reflect.TypeOf((*MockTokenRepositoryer)(nil).InsertToken), ctx, token)
}

// Remove mocks base method.
func (m *MockTokenRepositoryer) Remove(ctx context.Context, token *model.Token) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Remove", ctx, token)
	ret0, _ := ret[0].(error)
	return ret0
}

// Remove indicates an expected call of Remove.
func (mr *MockTokenRepositoryerMockRecorder) Remove(ctx, token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Remove", reflect.TypeOf((*MockTokenRepositoryer)(nil).Remove), ctx, token)
}

// Update mocks base method.
func (m *MockTokenRepositoryer) Update(ctx context.Context, token *model.Token) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", ctx, token)
	ret0, _ := ret[0].(error)
	return ret0
}

// Update indicates an expected call of Update.
func (mr *MockTokenRepositoryerMockRecorder) Update(ctx, token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockTokenRepositoryer)(nil).Update), ctx, token)
}

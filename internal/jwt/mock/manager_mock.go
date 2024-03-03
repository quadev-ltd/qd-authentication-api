// Code generated by MockGen. DO NOT EDIT.
// Source: manager.go

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"
	time "time"

	jwt "github.com/golang-jwt/jwt"
	gomock "github.com/golang/mock/gomock"
	jwt0 "github.com/quadev-ltd/qd-common/pkg/jwt"
)

// MockManagerer is a mock of Managerer interface.
type MockManagerer struct {
	ctrl     *gomock.Controller
	recorder *MockManagererMockRecorder
}

// MockManagererMockRecorder is the mock recorder for MockManagerer.
type MockManagererMockRecorder struct {
	mock *MockManagerer
}

// NewMockManagerer creates a new mock instance.
func NewMockManagerer(ctrl *gomock.Controller) *MockManagerer {
	mock := &MockManagerer{ctrl: ctrl}
	mock.recorder = &MockManagererMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockManagerer) EXPECT() *MockManagererMockRecorder {
	return m.recorder
}

// GetEmailFromToken mocks base method.
func (m *MockManagerer) GetEmailFromToken(token *jwt.Token) (*string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetEmailFromToken", token)
	ret0, _ := ret[0].(*string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetEmailFromToken indicates an expected call of GetEmailFromToken.
func (mr *MockManagererMockRecorder) GetEmailFromToken(token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetEmailFromToken", reflect.TypeOf((*MockManagerer)(nil).GetEmailFromToken), token)
}

// GetPublicKey mocks base method.
func (m *MockManagerer) GetPublicKey(ctx context.Context) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPublicKey", ctx)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPublicKey indicates an expected call of GetPublicKey.
func (mr *MockManagererMockRecorder) GetPublicKey(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPublicKey", reflect.TypeOf((*MockManagerer)(nil).GetPublicKey), ctx)
}

// SignToken mocks base method.
func (m *MockManagerer) SignToken(email string, expiry time.Time, tokenType jwt0.TokenType) (*string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SignToken", email, expiry, tokenType)
	ret0, _ := ret[0].(*string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SignToken indicates an expected call of SignToken.
func (mr *MockManagererMockRecorder) SignToken(email, expiry, tokenType interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignToken", reflect.TypeOf((*MockManagerer)(nil).SignToken), email, expiry, tokenType)
}

// VerifyToken mocks base method.
func (m *MockManagerer) VerifyToken(token string) (*jwt.Token, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyToken", token)
	ret0, _ := ret[0].(*jwt.Token)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyToken indicates an expected call of VerifyToken.
func (mr *MockManagererMockRecorder) VerifyToken(token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyToken", reflect.TypeOf((*MockManagerer)(nil).VerifyToken), token)
}
// Code generated by MockGen. DO NOT EDIT.
// Source: jwt_signer.go

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"
	time "time"

	jwt "github.com/golang-jwt/jwt"
	gomock "github.com/golang/mock/gomock"
)

// MockJWTSignerer is a mock of JWTSignerer interface.
type MockJWTSignerer struct {
	ctrl     *gomock.Controller
	recorder *MockJWTSignererMockRecorder
}

// MockJWTSignererMockRecorder is the mock recorder for MockJWTSignerer.
type MockJWTSignererMockRecorder struct {
	mock *MockJWTSignerer
}

// NewMockJWTSignerer creates a new mock instance.
func NewMockJWTSignerer(ctrl *gomock.Controller) *MockJWTSignerer {
	mock := &MockJWTSignerer{ctrl: ctrl}
	mock.recorder = &MockJWTSignererMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockJWTSignerer) EXPECT() *MockJWTSignererMockRecorder {
	return m.recorder
}

// GenerateNewKeyPair mocks base method.
func (m *MockJWTSignerer) GenerateNewKeyPair() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GenerateNewKeyPair")
	ret0, _ := ret[0].(error)
	return ret0
}

// GenerateNewKeyPair indicates an expected call of GenerateNewKeyPair.
func (mr *MockJWTSignererMockRecorder) GenerateNewKeyPair() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateNewKeyPair", reflect.TypeOf((*MockJWTSignerer)(nil).GenerateNewKeyPair))
}

// GetEmailFromToken mocks base method.
func (m *MockJWTSignerer) GetEmailFromToken(token *jwt.Token) (*string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetEmailFromToken", token)
	ret0, _ := ret[0].(*string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetEmailFromToken indicates an expected call of GetEmailFromToken.
func (mr *MockJWTSignererMockRecorder) GetEmailFromToken(token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetEmailFromToken", reflect.TypeOf((*MockJWTSignerer)(nil).GetEmailFromToken), token)
}

// GetExpiryFromToken mocks base method.
func (m *MockJWTSignerer) GetExpiryFromToken(token *jwt.Token) (*time.Time, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetExpiryFromToken", token)
	ret0, _ := ret[0].(*time.Time)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetExpiryFromToken indicates an expected call of GetExpiryFromToken.
func (mr *MockJWTSignererMockRecorder) GetExpiryFromToken(token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetExpiryFromToken", reflect.TypeOf((*MockJWTSignerer)(nil).GetExpiryFromToken), token)
}

// GetPublicKey mocks base method.
func (m *MockJWTSignerer) GetPublicKey(ctx context.Context) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPublicKey", ctx)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPublicKey indicates an expected call of GetPublicKey.
func (mr *MockJWTSignererMockRecorder) GetPublicKey(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPublicKey", reflect.TypeOf((*MockJWTSignerer)(nil).GetPublicKey), ctx)
}

// SignToken mocks base method.
func (m *MockJWTSignerer) SignToken(email string, expiry time.Time) (*string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SignToken", email, expiry)
	ret0, _ := ret[0].(*string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SignToken indicates an expected call of SignToken.
func (mr *MockJWTSignererMockRecorder) SignToken(email, expiry interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignToken", reflect.TypeOf((*MockJWTSignerer)(nil).SignToken), email, expiry)
}

// VerifyToken mocks base method.
func (m *MockJWTSignerer) VerifyToken(token string) (*jwt.Token, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyToken", token)
	ret0, _ := ret[0].(*jwt.Token)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyToken indicates an expected call of VerifyToken.
func (mr *MockJWTSignererMockRecorder) VerifyToken(token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyToken", reflect.TypeOf((*MockJWTSignerer)(nil).VerifyToken), token)
}

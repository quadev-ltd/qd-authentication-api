// Code generated by MockGen. DO NOT EDIT.
// Source: user_repository.go

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	model "qd-authentication-api/internal/model"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	primitive "go.mongodb.org/mongo-driver/bson/primitive"
)

// MockUserRepositoryer is a mock of UserRepositoryer interface.
type MockUserRepositoryer struct {
	ctrl     *gomock.Controller
	recorder *MockUserRepositoryerMockRecorder
}

// MockUserRepositoryerMockRecorder is the mock recorder for MockUserRepositoryer.
type MockUserRepositoryerMockRecorder struct {
	mock *MockUserRepositoryer
}

// NewMockUserRepositoryer creates a new mock instance.
func NewMockUserRepositoryer(ctrl *gomock.Controller) *MockUserRepositoryer {
	mock := &MockUserRepositoryer{ctrl: ctrl}
	mock.recorder = &MockUserRepositoryerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockUserRepositoryer) EXPECT() *MockUserRepositoryerMockRecorder {
	return m.recorder
}

// DeleteByUserID mocks base method.
func (m *MockUserRepositoryer) DeleteByUserID(ctx context.Context, userID primitive.ObjectID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteByUserID", ctx, userID)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteByUserID indicates an expected call of DeleteByUserID.
func (mr *MockUserRepositoryerMockRecorder) DeleteByUserID(ctx, userID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteByUserID", reflect.TypeOf((*MockUserRepositoryer)(nil).DeleteByUserID), ctx, userID)
}

// ExistsByEmail mocks base method.
func (m *MockUserRepositoryer) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExistsByEmail", ctx, email)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ExistsByEmail indicates an expected call of ExistsByEmail.
func (mr *MockUserRepositoryerMockRecorder) ExistsByEmail(ctx, email interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExistsByEmail", reflect.TypeOf((*MockUserRepositoryer)(nil).ExistsByEmail), ctx, email)
}

// GetByEmail mocks base method.
func (m *MockUserRepositoryer) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByEmail", ctx, email)
	ret0, _ := ret[0].(*model.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByEmail indicates an expected call of GetByEmail.
func (mr *MockUserRepositoryerMockRecorder) GetByEmail(ctx, email interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByEmail", reflect.TypeOf((*MockUserRepositoryer)(nil).GetByEmail), ctx, email)
}

// GetByUserID mocks base method.
func (m *MockUserRepositoryer) GetByUserID(ctx context.Context, userID primitive.ObjectID) (*model.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByUserID", ctx, userID)
	ret0, _ := ret[0].(*model.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByUserID indicates an expected call of GetByUserID.
func (mr *MockUserRepositoryerMockRecorder) GetByUserID(ctx, userID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByUserID", reflect.TypeOf((*MockUserRepositoryer)(nil).GetByUserID), ctx, userID)
}

// InsertUser mocks base method.
func (m *MockUserRepositoryer) InsertUser(ctx context.Context, user *model.User) (interface{}, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InsertUser", ctx, user)
	ret0, _ := ret[0].(interface{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InsertUser indicates an expected call of InsertUser.
func (mr *MockUserRepositoryerMockRecorder) InsertUser(ctx, user interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertUser", reflect.TypeOf((*MockUserRepositoryer)(nil).InsertUser), ctx, user)
}

// UpdateAuthTypes mocks base method.
func (m *MockUserRepositoryer) UpdateAuthTypes(ctx context.Context, user *model.User) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateAuthTypes", ctx, user)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateAuthTypes indicates an expected call of UpdateAuthTypes.
func (mr *MockUserRepositoryerMockRecorder) UpdateAuthTypes(ctx, user interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateAuthTypes", reflect.TypeOf((*MockUserRepositoryer)(nil).UpdateAuthTypes), ctx, user)
}

// UpdatePassword mocks base method.
func (m *MockUserRepositoryer) UpdatePassword(ctx context.Context, user *model.User) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdatePassword", ctx, user)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdatePassword indicates an expected call of UpdatePassword.
func (mr *MockUserRepositoryerMockRecorder) UpdatePassword(ctx, user interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdatePassword", reflect.TypeOf((*MockUserRepositoryer)(nil).UpdatePassword), ctx, user)
}

// UpdateProfileDetails mocks base method.
func (m *MockUserRepositoryer) UpdateProfileDetails(ctx context.Context, user *model.User) (*model.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateProfileDetails", ctx, user)
	ret0, _ := ret[0].(*model.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateProfileDetails indicates an expected call of UpdateProfileDetails.
func (mr *MockUserRepositoryerMockRecorder) UpdateProfileDetails(ctx, user interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateProfileDetails", reflect.TypeOf((*MockUserRepositoryer)(nil).UpdateProfileDetails), ctx, user)
}

// UpdateStatus mocks base method.
func (m *MockUserRepositoryer) UpdateStatus(ctx context.Context, user *model.User) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateStatus", ctx, user)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateStatus indicates an expected call of UpdateStatus.
func (mr *MockUserRepositoryerMockRecorder) UpdateStatus(ctx, user interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateStatus", reflect.TypeOf((*MockUserRepositoryer)(nil).UpdateStatus), ctx, user)
}

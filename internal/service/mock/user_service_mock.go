// Code generated by MockGen. DO NOT EDIT.
// Source: user_service.go

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	model "qd-authentication-api/internal/model"
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	pb_authentication "github.com/quadev-ltd/qd-common/pb/gen/go/pb_authentication"
)

// MockUserServicer is a mock of UserServicer interface.
type MockUserServicer struct {
	ctrl     *gomock.Controller
	recorder *MockUserServicerMockRecorder
}

// MockUserServicerMockRecorder is the mock recorder for MockUserServicer.
type MockUserServicerMockRecorder struct {
	mock *MockUserServicer
}

// NewMockUserServicer creates a new mock instance.
func NewMockUserServicer(ctrl *gomock.Controller) *MockUserServicer {
	mock := &MockUserServicer{ctrl: ctrl}
	mock.recorder = &MockUserServicerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockUserServicer) EXPECT() *MockUserServicerMockRecorder {
	return m.recorder
}

// Authenticate mocks base method.
func (m *MockUserServicer) Authenticate(ctx context.Context, email, password string) (*model.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Authenticate", ctx, email, password)
	ret0, _ := ret[0].(*model.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Authenticate indicates an expected call of Authenticate.
func (mr *MockUserServicerMockRecorder) Authenticate(ctx, email, password interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Authenticate", reflect.TypeOf((*MockUserServicer)(nil).Authenticate), ctx, email, password)
}

// AuthenticateWithFirebase mocks base method.
func (m *MockUserServicer) AuthenticateWithFirebase(ctx context.Context, idToken, email, firstName, lastName string) (*model.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthenticateWithFirebase", ctx, idToken, email, firstName, lastName)
	ret0, _ := ret[0].(*model.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthenticateWithFirebase indicates an expected call of AuthenticateWithFirebase.
func (mr *MockUserServicerMockRecorder) AuthenticateWithFirebase(ctx, idToken, email, firstName, lastName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthenticateWithFirebase", reflect.TypeOf((*MockUserServicer)(nil).AuthenticateWithFirebase), ctx, idToken, email, firstName, lastName)
}

// DeleteUser mocks base method.
func (m *MockUserServicer) DeleteUser(ctx context.Context, userID string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteUser", ctx, userID)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteUser indicates an expected call of DeleteUser.
func (mr *MockUserServicerMockRecorder) DeleteUser(ctx, userID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteUser", reflect.TypeOf((*MockUserServicer)(nil).DeleteUser), ctx, userID)
}

// GetUserByID mocks base method.
func (m *MockUserServicer) GetUserByID(ctx context.Context, userID string) (*model.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserByID", ctx, userID)
	ret0, _ := ret[0].(*model.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserByID indicates an expected call of GetUserByID.
func (mr *MockUserServicerMockRecorder) GetUserByID(ctx, userID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserByID", reflect.TypeOf((*MockUserServicer)(nil).GetUserByID), ctx, userID)
}

// GetUserProfile mocks base method.
func (m *MockUserServicer) GetUserProfile(ctx context.Context, userID string) (*model.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserProfile", ctx, userID)
	ret0, _ := ret[0].(*model.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserProfile indicates an expected call of GetUserProfile.
func (mr *MockUserServicerMockRecorder) GetUserProfile(ctx, userID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserProfile", reflect.TypeOf((*MockUserServicer)(nil).GetUserProfile), ctx, userID)
}

// Register mocks base method.
func (m *MockUserServicer) Register(ctx context.Context, email, password, firstName, lastName string, dateOfBirth *time.Time) (*model.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Register", ctx, email, password, firstName, lastName, dateOfBirth)
	ret0, _ := ret[0].(*model.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Register indicates an expected call of Register.
func (mr *MockUserServicerMockRecorder) Register(ctx, email, password, firstName, lastName, dateOfBirth interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Register", reflect.TypeOf((*MockUserServicer)(nil).Register), ctx, email, password, firstName, lastName, dateOfBirth)
}

// ResendEmailVerification mocks base method.
func (m *MockUserServicer) ResendEmailVerification(ctx context.Context, email *model.User, emailVerificationToken string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResendEmailVerification", ctx, email, emailVerificationToken)
	ret0, _ := ret[0].(error)
	return ret0
}

// ResendEmailVerification indicates an expected call of ResendEmailVerification.
func (mr *MockUserServicerMockRecorder) ResendEmailVerification(ctx, email, emailVerificationToken interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResendEmailVerification", reflect.TypeOf((*MockUserServicer)(nil).ResendEmailVerification), ctx, email, emailVerificationToken)
}

// SendEmailVerification mocks base method.
func (m *MockUserServicer) SendEmailVerification(ctx context.Context, user *model.User, emailVerificationToken string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendEmailVerification", ctx, user, emailVerificationToken)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendEmailVerification indicates an expected call of SendEmailVerification.
func (mr *MockUserServicerMockRecorder) SendEmailVerification(ctx, user, emailVerificationToken interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendEmailVerification", reflect.TypeOf((*MockUserServicer)(nil).SendEmailVerification), ctx, user, emailVerificationToken)
}

// UpdateProfileDetails mocks base method.
func (m *MockUserServicer) UpdateProfileDetails(ctx context.Context, userID string, profileDetails *pb_authentication.UpdateUserProfileRequest) (*model.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateProfileDetails", ctx, userID, profileDetails)
	ret0, _ := ret[0].(*model.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateProfileDetails indicates an expected call of UpdateProfileDetails.
func (mr *MockUserServicerMockRecorder) UpdateProfileDetails(ctx, userID, profileDetails interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateProfileDetails", reflect.TypeOf((*MockUserServicer)(nil).UpdateProfileDetails), ctx, userID, profileDetails)
}

// VerifyEmail mocks base method.
func (m *MockUserServicer) VerifyEmail(ctx context.Context, token *model.Token) (*model.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyEmail", ctx, token)
	ret0, _ := ret[0].(*model.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyEmail indicates an expected call of VerifyEmail.
func (mr *MockUserServicerMockRecorder) VerifyEmail(ctx, token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyEmail", reflect.TypeOf((*MockUserServicer)(nil).VerifyEmail), ctx, token)
}

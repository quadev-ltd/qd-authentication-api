package mock

import (
	"qd_authentication_api/internal/model"
)

type MockUserRepository struct {
	Users []model.User
}

func (m *MockUserRepository) Create(user *model.User) error {
	m.Users = append(m.Users, *user)
	return nil
}

func (m *MockUserRepository) GetByEmail(email string) (*model.User, error) {
	for _, user := range m.Users {
		if user.Email == email {
			return &user, nil
		}
	}
	return nil, nil
}

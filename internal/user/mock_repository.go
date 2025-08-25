package user

// Mock implementation for UserRepository interface for unit tests

type MockUserRepository struct {
	CreateUserFunc     func(user *User) error
	GetUserByEmailFunc func(email string) (*User, error)
	GetUserByIDFunc    func(id int64) (*User, error)
}

func (m *MockUserRepository) CreateUser(user *User) error {
	return m.CreateUserFunc(user)
}

func (m *MockUserRepository) GetUserByEmail(email string) (*User, error) {
	return m.GetUserByEmailFunc(email)
}

func (m *MockUserRepository) GetUserByID(id int64) (*User, error) {
	if m.GetUserByIDFunc != nil {
		return m.GetUserByIDFunc(id)
	}
	return nil, nil
}

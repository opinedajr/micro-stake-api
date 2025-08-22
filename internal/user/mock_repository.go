package user

// Mock implementation for UserRepository interface for unit tests

type MockUserRepository struct {
	CreateUserFunc     func(user *User) error
	GetUserByEmailFunc func(email string) (*User, error)
}

func (m *MockUserRepository) CreateUser(user *User) error {
	return m.CreateUserFunc(user)
}

func (m *MockUserRepository) GetUserByEmail(email string) (*User, error) {
	return m.GetUserByEmailFunc(email)
}

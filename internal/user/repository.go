package user

// UserRepository defines persistence operations for User
// Comments in English (US)
type UserRepository interface {
	CreateUser(user *User) error
	GetUserByEmail(email string) (*User, error)
	GetUserByID(id int64) (*User, error)
}

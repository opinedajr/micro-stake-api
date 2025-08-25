package postgres

import (
	"micro-stake/internal/user"

	"gorm.io/gorm"
)

// PostgresUserRepository implements user.UserRepository using GORM/Postgres
// Comments in English (US)
type PostgresUserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) user.UserRepository {
	return &PostgresUserRepository{db: db}
}

func (r *PostgresUserRepository) CreateUser(u *user.User) error {
	return r.db.Create(u).Error
}

func (r *PostgresUserRepository) GetUserByEmail(email string) (*user.User, error) {
	var u user.User
	result := r.db.Where("email = ?", email).First(&u)
	if result.Error != nil {
		return nil, result.Error
	}
	return &u, nil
}

func (r *PostgresUserRepository) GetUserByID(id int64) (*user.User, error) {
	var u user.User
	err := r.db.Where("id = ?", id).First(&u).Error
	if err != nil {
		return nil, err
	}
	return &u, nil
}

package postgres

import (
	"micro-stake/internal/user"
	"testing"

	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err)
	// Migrar a tabela de usuários
	err = db.AutoMigrate(&user.User{})
	assert.NoError(t, err)
	return db
}

func TestPostgresUserRepository_CreateUserAndGetUserByEmail(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	u := &user.User{
		Email:        "test@email.com",
		PasswordHash: "hash",
		FirstName:    "John",
		LastName:     "Doe",
	}

	err := repo.CreateUser(u)
	assert.NoError(t, err)
	assert.NotZero(t, u.ID)

	found, err := repo.GetUserByEmail("test@email.com")
	assert.NoError(t, err)
	assert.NotNil(t, found)
	assert.Equal(t, "John", found.FirstName)
	assert.Equal(t, "Doe", found.LastName)
}

func TestPostgresUserRepository_GetUserByEmail_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	found, err := repo.GetUserByEmail("notfound@email.com")
	assert.Error(t, err)
	assert.Nil(t, found)
}

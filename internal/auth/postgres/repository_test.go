package postgres

import (
	"micro-stake/internal/auth"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB() *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	db.AutoMigrate(&auth.RefreshToken{})
	return db
}

func TestPostgresRefreshTokenRepository_CreateAndGetByToken(t *testing.T) {
	db := setupTestDB()
	repo := NewRefreshTokenRepository(db)

	token := &auth.RefreshToken{
		Token:     "test-token",
		UserID:    "1",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	err := repo.Create(token)
	assert.NoError(t, err)

	found, err := repo.GetByToken("test-token")
	assert.NoError(t, err)
	assert.NotNil(t, found)
	assert.Equal(t, "test-token", found.Token)
}

func TestPostgresRefreshTokenRepository_GetByToken_NotFound(t *testing.T) {
	db := setupTestDB()
	repo := NewRefreshTokenRepository(db)

	found, err := repo.GetByToken("not-exist")
	assert.NoError(t, err)
	assert.Nil(t, found)
}

func TestPostgresRefreshTokenRepository_Revoke(t *testing.T) {
	db := setupTestDB()
	repo := NewRefreshTokenRepository(db)

	token := &auth.RefreshToken{
		Token:     "revoke-token",
		UserID:    "2",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	repo.Create(token)

	found, _ := repo.GetByToken("revoke-token")
	assert.False(t, found.IsRevoked)

	revokedAt := time.Now()
	err := repo.Revoke(found.ID, revokedAt)
	assert.NoError(t, err)

	updated, _ := repo.GetByToken("revoke-token")
	assert.True(t, updated.IsRevoked)
	if updated.RevokedAt != nil {
		assert.WithinDuration(t, revokedAt, *updated.RevokedAt, time.Second)
	}
}

func TestPostgresRefreshTokenRepository_Create_Error(t *testing.T) {
	db := setupTestDB()
	repo := NewRefreshTokenRepository(db)
	// Simula erro passando struct inválida
	err := repo.Create(nil)
	assert.Error(t, err)
}

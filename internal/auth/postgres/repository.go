package postgres

import (
	"micro-stake/internal/auth"
	"time"

	"gorm.io/gorm"
)

// PostgresRefreshTokenRepository implements auth.RefreshTokenRepository for PostgreSQL
// Comments in English (US)
type PostgresRefreshTokenRepository struct {
	db *gorm.DB
}

func NewRefreshTokenRepository(db *gorm.DB) *PostgresRefreshTokenRepository {
	return &PostgresRefreshTokenRepository{db: db}
}

func (r *PostgresRefreshTokenRepository) Create(token *auth.RefreshToken) error {
	return r.db.Create(token).Error
}

func (r *PostgresRefreshTokenRepository) GetByToken(token string) (*auth.RefreshToken, error) {
	var rt auth.RefreshToken
	err := r.db.Where("token = ?", token).First(&rt).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &rt, nil
}

func (r *PostgresRefreshTokenRepository) Revoke(tokenID int64, revokedAt time.Time) error {
	return r.db.Model(&auth.RefreshToken{}).
		Where("id = ?", tokenID).
		Updates(map[string]interface{}{
			"is_revoked": true,
			"revoked_at": revokedAt,
			"updated_at": time.Now(),
		}).Error
}

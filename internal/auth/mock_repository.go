package auth

import (
	"time"
)

// MockRefreshTokenRepository is a mock implementation for unit tests
type MockRefreshTokenRepository struct {
	CreateFunc     func(token *RefreshToken) error
	GetByTokenFunc func(token string) (*RefreshToken, error)
	RevokeFunc     func(tokenID int64, revokedAt time.Time) error
}

func (m *MockRefreshTokenRepository) Create(token *RefreshToken) error {
	if m.CreateFunc != nil {
		return m.CreateFunc(token)
	}
	return nil
}

func (m *MockRefreshTokenRepository) GetByToken(token string) (*RefreshToken, error) {
	if m.GetByTokenFunc != nil {
		return m.GetByTokenFunc(token)
	}
	return nil, nil
}

func (m *MockRefreshTokenRepository) Revoke(tokenID int64, revokedAt time.Time) error {
	if m.RevokeFunc != nil {
		return m.RevokeFunc(tokenID, revokedAt)
	}
	return nil
}

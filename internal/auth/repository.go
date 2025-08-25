package auth

import "time"

// RefreshTokenRepository defines the interface for manipulating refresh tokens
// Interface remains, struct is imported from model.go
// Comments in English (US)
type RefreshTokenRepository interface {
	Create(token *RefreshToken) error
	GetByToken(token string) (*RefreshToken, error)
	Revoke(tokenID int64, revokedAt time.Time) error
}

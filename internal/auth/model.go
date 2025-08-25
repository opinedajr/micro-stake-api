package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SignUpRequest represents the payload for user registration
type SignUpRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// LoginRequest represents the payload for user login
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse represents the response payload for user login
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	ExpiresAt    string `json:"expires_at"`
}

// SignUpResponse represents the response payload for user registration
type SignUpResponse struct {
	ID        int64  `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	CreatedAt string `json:"created_at"`
}

// RefreshTokenResponse represents the response for token refresh
type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	ExpiresAt    string `json:"expires_at"`
}

// RefreshTokenRequest represents the payload for refresh token operation
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
	UserAgent    string `json:"user_agent,omitempty"`
	IPAddress    string `json:"ip_address,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
}

// AccessClaims represents JWT claims for access tokens
type AccessClaims struct {
	Type      string `json:"type"`
	UserID    int64  `json:"user_id"`
	UserEmail string `json:"user_email"`
	jwt.RegisteredClaims
}

// RefreshClaims represents JWT claims for refresh tokens
type RefreshClaims struct {
	Type   string `json:"type"`
	UserID int64  `json:"user_id"`
	jwt.RegisteredClaims
}

// RefreshToken represents the refresh token model
type RefreshToken struct {
	ID        int64      `gorm:"primaryKey" json:"id"`
	Token     string     `json:"token"`
	UserID    string     `json:"user_id"`
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	IsRevoked bool       `json:"is_revoked"`
	RevokedAt *time.Time `json:"revoked_at"`
	UserAgent string     `json:"user_agent,omitempty"`
	IPAddress string     `json:"ip_address,omitempty"`
	DeviceID  string     `json:"device_id,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

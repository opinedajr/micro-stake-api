package user

import "time"

// User represents a platform user
// Fields based on PRD and migrations
// Comments in English (US)
type User struct {
	ID           int64      `json:"id"`
	Email        string     `json:"email"`
	PasswordHash string     `json:"password_hash"`
	FirstName    string     `json:"first_name"`
	LastName     string     `json:"last_name"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty"`
}

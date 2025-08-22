package auth

// SignUpRequest represents the payload for user registration
// Comments in English (US)
type SignUpRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// LoginRequest represents the payload for user login
// Comments in English (US)
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// SignUpResponse represents the response payload for user registration
// Comments in English (US)
type SignUpResponse struct {
	ID        int64  `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	CreatedAt string `json:"created_at"`
}

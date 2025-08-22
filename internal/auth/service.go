package auth

import (
	"errors"
	"micro-stake/internal/config"
	"micro-stake/internal/user"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"golang.org/x/crypto/bcrypt"
)

// AuthService defines authentication operations
type AuthService interface {
	SignUp(req SignUpRequest) (*SignUpResponse, error)
	Login(req LoginRequest) (string, error)
	GenerateJWT(userID int64, userEmail string) (string, error)
}

// Concrete implementation of AuthService
// Uses UserRepository for persistence
// JWT generation is stubbed for now

type authService struct {
	repo    user.UserRepository
	jwtConf config.JWTConfig
}

func NewAuthService(repo user.UserRepository, jwtConf config.JWTConfig) AuthService {
	return &authService{repo: repo, jwtConf: jwtConf}
}

func (s *authService) SignUp(req SignUpRequest) (*SignUpResponse, error) {
	// Check if user already exists
	existing, _ := s.repo.GetUserByEmail(req.Email)
	if existing != nil {
		return nil, errors.New("user already exists")
	}
	// Hash password securely
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.New("failed to hash password")
	}
	user := &user.User{
		Email:        req.Email,
		PasswordHash: string(hash),
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.repo.CreateUser(user); err != nil {
		return nil, err
	}
	resp := &SignUpResponse{
		ID:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
	}
	return resp, nil
}

func (s *authService) Login(req LoginRequest) (string, error) {
	u, err := s.repo.GetUserByEmail(req.Email)
	if err != nil || u == nil {
		return "", errors.New("invalid credentials")
	}
	// Compare password securely
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
		return "", errors.New("invalid credentials")
	}
	// Generate JWT com email
	return s.GenerateJWT(u.ID, u.Email)
}

type Claims struct {
	UserID    int64  `json:"user_id"`
	UserEmail string `json:"user_email"`
	jwt.RegisteredClaims
}

func (s *authService) GenerateJWT(userID int64, userEmail string) (string, error) {
	claims := Claims{
		UserID:    userID,
		UserEmail: userEmail,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(s.jwtConf.ExpirationHours) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(s.jwtConf.Secret))
	if err != nil {
		return "", err
	}
	return signed, nil
}

package auth

import (
	"errors"
	"fmt"
	"micro-stake/internal/config"
	"micro-stake/internal/user"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// AuthService defines authentication operations
type AuthService interface {
	SignUp(req SignUpRequest) (*SignUpResponse, error)
	Login(req LoginRequest) (*LoginResponse, error)
	RefreshToken(req RefreshTokenRequest) (*RefreshTokenResponse, error)
	GenerateAccessToken(userID int64, userEmail string, expiresAt time.Time) (string, error)
	GenerateRefreshToken(userID int64, expiresAt time.Time) (string, error)
}

// Concrete implementation of AuthService
// Uses UserRepository for persistence
// JWT generation is stubbed for now

type authService struct {
	repo        user.UserRepository
	jwtConf     config.JWTConfig
	refreshRepo RefreshTokenRepository
}

func NewAuthService(repo user.UserRepository, jwtConf config.JWTConfig, refreshRepo RefreshTokenRepository) AuthService {
	return &authService{repo: repo, jwtConf: jwtConf, refreshRepo: refreshRepo}
}

var bcryptGenerateFromPassword = bcrypt.GenerateFromPassword

func (s *authService) SignUp(req SignUpRequest) (*SignUpResponse, error) {
	// Check if user already exists
	existing, _ := s.repo.GetUserByEmail(req.Email)
	if existing != nil {
		return nil, errors.New("user already exists")
	}
	// Hash password securely
	hash, err := bcryptGenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
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

var jwtSignFunc = func(token *jwt.Token, secret string) (string, error) {
	return token.SignedString([]byte(secret))
}

func (s *authService) GenerateAccessToken(userID int64, userEmail string, expiresAt time.Time) (string, error) {
	claims := AccessClaims{
		Type:      "access",
		UserID:    userID,
		UserEmail: userEmail,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := jwtSignFunc(token, s.jwtConf.Secret)
	if err != nil {
		return "", err
	}
	return signed, nil
}

func (s *authService) GenerateRefreshToken(userID int64, expiresAt time.Time) (string, error) {
	claims := RefreshClaims{
		Type:   "refresh",
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := jwtSignFunc(token, s.jwtConf.Secret)
	if err != nil {
		return "", err
	}
	return signed, nil
}

func (s *authService) Login(req LoginRequest) (*LoginResponse, error) {
	u, err := s.repo.GetUserByEmail(req.Email)
	if err != nil || u == nil {
		return nil, errors.New("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
		return nil, errors.New("invalid credentials")
	}
	accessExpiresAt := time.Now().Add(time.Duration(s.jwtConf.ExpirationHours) * time.Hour)
	refreshExpiresAt := time.Now().Add(time.Duration(s.jwtConf.RefreshExpirationDays) * 24 * time.Hour)
	accessToken, err := s.GenerateAccessToken(u.ID, u.Email, accessExpiresAt)
	if err != nil {
		return nil, err
	}
	refreshToken, err := s.GenerateRefreshToken(u.ID, refreshExpiresAt)
	if err != nil {
		return nil, err
	}
	// Persist refresh token
	newRefresh := &RefreshToken{
		Token:     refreshToken,
		UserID:    parseUserIDToString(u.ID),
		IssuedAt:  time.Now(),
		ExpiresAt: refreshExpiresAt,
	}
	if err := s.refreshRepo.Create(newRefresh); err != nil {
		return nil, err
	}
	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(time.Until(accessExpiresAt).Seconds()),
		ExpiresAt:    accessExpiresAt.Format(time.RFC3339),
	}, nil
}

// RefreshToken implements the refresh token rotation logic
func (s *authService) RefreshToken(req RefreshTokenRequest) (*RefreshTokenResponse, error) {
	token, err := s.refreshRepo.GetByToken(req.RefreshToken)
	if err != nil || token == nil {
		return nil, errors.New("invalid refresh token")
	}
	if token.IsRevoked {
		return nil, errors.New("token revoked")
	}
	if token.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("token expired")
	}
	// Revoke old token
	revokedAt := time.Now()
	if err := s.refreshRepo.Revoke(token.ID, revokedAt); err != nil {
		return nil, err
	}
	userIDInt64, err := parseUserID(token.UserID)
	if err != nil {
		return nil, errors.New("invalid user id")
	}
	accessExpiresAt := time.Now().Add(time.Duration(s.jwtConf.ExpirationHours) * time.Hour)
	userEmail := ""
	if u, err := s.repo.GetUserByID(userIDInt64); err == nil && u != nil {
		userEmail = u.Email
	}
	accessToken, err := s.GenerateAccessToken(userIDInt64, userEmail, accessExpiresAt)
	if err != nil {
		return nil, err
	}
	refreshExpiresAt := time.Now().Add(time.Duration(s.jwtConf.RefreshExpirationDays) * 24 * time.Hour)
	refreshToken, err := s.GenerateRefreshToken(userIDInt64, refreshExpiresAt)
	if err != nil {
		return nil, err
	}
	newRefresh := &RefreshToken{
		ID:        token.ID + 1, // ou gere um novo ID conforme sua lógica
		Token:     refreshToken,
		UserID:    token.UserID,
		IssuedAt:  time.Now(),
		ExpiresAt: refreshExpiresAt,
		UserAgent: req.UserAgent,
		IPAddress: req.IPAddress,
		DeviceID:  req.DeviceID,
	}
	if err := s.refreshRepo.Create(newRefresh); err != nil {
		return nil, err
	}
	return &RefreshTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(time.Until(accessExpiresAt).Seconds()),
		ExpiresAt:    accessExpiresAt.Format(time.RFC3339),
	}, nil
}

// parseUserID converts string userID to int64
func parseUserID(id string) (int64, error) {
	return strconv.ParseInt(id, 10, 64)
}

func parseUserIDToString(id int64) string {
	return fmt.Sprintf("%d", id)
}

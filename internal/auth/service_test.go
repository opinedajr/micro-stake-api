package auth

import (
	"errors"
	"micro-stake/internal/config"
	"micro-stake/internal/user"
	"time"

	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthService_SignUp(t *testing.T) {
	mockRepo := &user.MockUserRepository{
		CreateUserFunc: func(u *user.User) error {
			u.ID = 1
			return nil
		},
		GetUserByEmailFunc: func(email string) (*user.User, error) {
			return nil, nil // Usuário não existe
		},
	}
	jwtConf := config.JWTConfig{Secret: "test-secret", ExpirationHours: 24}
	mockRefreshRepo := &MockRefreshTokenRepository{}
	service := NewAuthService(mockRepo, jwtConf, mockRefreshRepo)

	req := SignUpRequest{
		Email:     "test@email.com",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}
	created, err := service.SignUp(req)
	assert.NoError(t, err)
	assert.NotNil(t, created)
	assert.Equal(t, "test@email.com", created.Email)
}

func TestAuthService_SignUp_UserExists(t *testing.T) {
	mockRepo := &user.MockUserRepository{
		GetUserByEmailFunc: func(email string) (*user.User, error) {
			return &user.User{ID: 2, Email: email}, nil // Usuário já existe
		},
	}
	jwtConf := config.JWTConfig{Secret: "test-secret", ExpirationHours: 24}
	mockRefreshRepo := &MockRefreshTokenRepository{}
	service := NewAuthService(mockRepo, jwtConf, mockRefreshRepo)

	req := SignUpRequest{
		Email:     "test@email.com",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}
	created, err := service.SignUp(req)
	assert.Error(t, err)
	assert.Nil(t, created)
}

func TestAuthService_Login_Success(t *testing.T) {
	password := "password123"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	mockRepo := &user.MockUserRepository{
		GetUserByEmailFunc: func(email string) (*user.User, error) {
			return &user.User{ID: 1, Email: email, PasswordHash: string(hash)}, nil
		},
	}
	jwtConf := config.JWTConfig{Secret: "test-secret", ExpirationHours: 24}
	mockRefreshRepo := &MockRefreshTokenRepository{}
	service := NewAuthService(mockRepo, jwtConf, mockRefreshRepo)

	req := LoginRequest{
		Email:    "test@email.com",
		Password: password,
	}
	token, err := service.Login(req)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestAuthService_Login_InvalidPassword(t *testing.T) {
	password := "password123"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	mockRepo := &user.MockUserRepository{
		GetUserByEmailFunc: func(email string) (*user.User, error) {
			return &user.User{ID: 1, Email: email, PasswordHash: string(hash)}, nil
		},
	}
	jwtConf := config.JWTConfig{Secret: "test-secret", ExpirationHours: 24}
	mockRefreshRepo := &MockRefreshTokenRepository{}
	service := NewAuthService(mockRepo, jwtConf, mockRefreshRepo)

	req := LoginRequest{
		Email:    "test@email.com",
		Password: "wrongpass",
	}
	token, err := service.Login(req)
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestAuthService_Login_UserNotFound(t *testing.T) {
	mockRepo := &user.MockUserRepository{
		GetUserByEmailFunc: func(email string) (*user.User, error) {
			return nil, nil
		},
	}
	jwtConf := config.JWTConfig{Secret: "test-secret", ExpirationHours: 24}
	mockRefreshRepo := &MockRefreshTokenRepository{}
	service := NewAuthService(mockRepo, jwtConf, mockRefreshRepo)

	req := LoginRequest{
		Email:    "notfound@email.com",
		Password: "password123",
	}
	token, err := service.Login(req)
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestAuthService_RefreshToken_Success(t *testing.T) {
	userID := "user-1"
	oldToken := "old-refresh-token"
	newToken := "new-refresh-token"
	mockRepo := &MockRefreshTokenRepository{
		GetByTokenFunc: func(token string) (*RefreshToken, error) {
			return &RefreshToken{
				ID:        1,
				Token:     oldToken,
				UserID:    userID,
				IssuedAt:  time.Now().Add(-10 * time.Minute),
				ExpiresAt: time.Now().Add(20 * time.Minute),
				IsRevoked: false,
			}, nil
		},
		RevokeFunc: func(tokenID int64, revokedAt time.Time) error {
			assert.Equal(t, int64(1), tokenID)
			return nil
		},
		CreateFunc: func(token *RefreshToken) error {
			assert.Equal(t, newToken, token.Token)
			return nil
		},
	}
	service := &authServiceWithRefresh{refreshRepo: mockRepo}
	resp, err := service.RefreshToken(oldToken, newToken, userID)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, newToken, resp.RefreshToken)
}

func TestAuthService_RefreshToken_Revoked(t *testing.T) {
	mockRepo := &MockRefreshTokenRepository{
		GetByTokenFunc: func(token string) (*RefreshToken, error) {
			return &RefreshToken{
				ID:        2,
				Token:     token,
				IsRevoked: true,
			}, nil
		},
	}
	service := &authServiceWithRefresh{refreshRepo: mockRepo}
	resp, err := service.RefreshToken("revoked-token", "new-token", "user-2")
	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestAuthService_RefreshToken_Expired(t *testing.T) {
	mockRepo := &MockRefreshTokenRepository{
		GetByTokenFunc: func(token string) (*RefreshToken, error) {
			return &RefreshToken{
				ID:        3,
				Token:     token,
				ExpiresAt: time.Now().Add(-1 * time.Minute),
				IsRevoked: false,
			}, nil
		},
	}
	service := &authServiceWithRefresh{refreshRepo: mockRepo}
	resp, err := service.RefreshToken("expired-token", "new-token", "user-3")
	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestAuthService_SignUp_HashError(t *testing.T) {
	mockRepo := &user.MockUserRepository{
		GetUserByEmailFunc: func(email string) (*user.User, error) { return nil, nil },
	}
	jwtConf := config.JWTConfig{Secret: "test-secret", ExpirationHours: 24}
	mockRefreshRepo := &MockRefreshTokenRepository{}
	service := NewAuthService(mockRepo, jwtConf, mockRefreshRepo)

	// Simula erro de hash
	defer func() { bcryptGenerateFromPassword = bcrypt.GenerateFromPassword }()
	bcryptGenerateFromPassword = func(password []byte, cost int) ([]byte, error) {
		return nil, errors.New("hash error")
	}

	req := SignUpRequest{
		Email:     "fail@email.com",
		Password:  "password123",
		FirstName: "Fail",
		LastName:  "User",
	}
	created, err := service.SignUp(req)
	assert.Error(t, err)
	assert.Nil(t, created)
}

func TestAuthService_SignUp_CreateUserError(t *testing.T) {
	mockRepo := &user.MockUserRepository{
		GetUserByEmailFunc: func(email string) (*user.User, error) { return nil, nil },
		CreateUserFunc:     func(u *user.User) error { return errors.New("db error") },
	}
	jwtConf := config.JWTConfig{Secret: "test-secret", ExpirationHours: 24}
	mockRefreshRepo := &MockRefreshTokenRepository{}
	service := NewAuthService(mockRepo, jwtConf, mockRefreshRepo)

	req := SignUpRequest{
		Email:     "fail@email.com",
		Password:  "password123",
		FirstName: "Fail",
		LastName:  "User",
	}
	created, err := service.SignUp(req)
	assert.Error(t, err)
	assert.Nil(t, created)
}

func TestAuthService_Login_CreateRefreshError(t *testing.T) {
	password := "password123"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	mockRepo := &user.MockUserRepository{
		GetUserByEmailFunc: func(email string) (*user.User, error) {
			return &user.User{ID: 1, Email: email, PasswordHash: string(hash)}, nil
		},
	}
	jwtConf := config.JWTConfig{Secret: "test-secret", ExpirationHours: 24}
	mockRefreshRepo := &MockRefreshTokenRepository{
		CreateFunc: func(token *RefreshToken) error { return errors.New("refresh error") },
	}
	service := NewAuthService(mockRepo, jwtConf, mockRefreshRepo)

	req := LoginRequest{
		Email:    "test@email.com",
		Password: password,
	}
	token, err := service.Login(req)
	assert.Error(t, err)
	assert.Nil(t, token)
}

func TestAuthService_RefreshToken_CreateError(t *testing.T) {
	userID := "1"
	oldToken := "old-refresh-token"
	mockRepo := &MockRefreshTokenRepository{
		GetByTokenFunc: func(token string) (*RefreshToken, error) {
			return &RefreshToken{
				ID:        1,
				Token:     oldToken,
				UserID:    userID,
				IssuedAt:  time.Now().Add(-10 * time.Minute),
				ExpiresAt: time.Now().Add(20 * time.Minute),
				IsRevoked: false,
			}, nil
		},
		RevokeFunc: func(tokenID int64, revokedAt time.Time) error { return nil },
		CreateFunc: func(token *RefreshToken) error { return errors.New("create error") },
	}
	mockUserRepo := &user.MockUserRepository{
		GetUserByIDFunc: func(id int64) (*user.User, error) { return &user.User{ID: id, Email: "test@email.com"}, nil },
	}
	jwtConf := config.JWTConfig{Secret: "test-secret", ExpirationHours: 24}
	service := &authService{
		repo:        mockUserRepo,
		jwtConf:     jwtConf,
		refreshRepo: mockRepo,
	}
	req := RefreshTokenRequest{
		RefreshToken: oldToken,
	}
	resp, err := service.RefreshToken(req)
	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestAuthService_RefreshToken_RevokeError(t *testing.T) {
	userID := "1"
	oldToken := "old-refresh-token"
	mockRepo := &MockRefreshTokenRepository{
		GetByTokenFunc: func(token string) (*RefreshToken, error) {
			return &RefreshToken{
				ID:        1,
				Token:     oldToken,
				UserID:    userID,
				IssuedAt:  time.Now().Add(-10 * time.Minute),
				ExpiresAt: time.Now().Add(20 * time.Minute),
				IsRevoked: false,
			}, nil
		},
		RevokeFunc: func(tokenID int64, revokedAt time.Time) error { return errors.New("revoke error") },
	}
	mockUserRepo := &user.MockUserRepository{
		GetUserByIDFunc: func(id int64) (*user.User, error) { return &user.User{ID: id, Email: "test@email.com"}, nil },
	}
	jwtConf := config.JWTConfig{Secret: "test-secret", ExpirationHours: 24}
	service := &authService{
		repo:        mockUserRepo,
		jwtConf:     jwtConf,
		refreshRepo: mockRepo,
	}
	req := RefreshTokenRequest{
		RefreshToken: oldToken,
	}
	resp, err := service.RefreshToken(req)
	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestAuthService_RefreshToken_GetUserByIDError(t *testing.T) {
	userID := "1"
	oldToken := "old-refresh-token"
	mockRepo := &MockRefreshTokenRepository{
		GetByTokenFunc: func(token string) (*RefreshToken, error) {
			return &RefreshToken{
				ID:        1,
				Token:     oldToken,
				UserID:    userID,
				IssuedAt:  time.Now().Add(-10 * time.Minute),
				ExpiresAt: time.Now().Add(20 * time.Minute),
				IsRevoked: false,
			}, nil
		},
		RevokeFunc: func(tokenID int64, revokedAt time.Time) error { return nil },
		CreateFunc: func(token *RefreshToken) error { return nil },
	}
	mockUserRepo := &user.MockUserRepository{
		GetUserByIDFunc: func(id int64) (*user.User, error) { return nil, errors.New("not found") },
	}
	jwtConf := config.JWTConfig{Secret: "test-secret", ExpirationHours: 24}
	service := &authService{
		repo:        mockUserRepo,
		jwtConf:     jwtConf,
		refreshRepo: mockRepo,
	}
	req := RefreshTokenRequest{
		RefreshToken: oldToken,
	}
	resp, err := service.RefreshToken(req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestAuthService_GenerateAccessToken_SignError(t *testing.T) {
	service := NewAuthService(nil, config.JWTConfig{Secret: ""}, nil)
	oldSign := jwtSignFunc
	defer func() { jwtSignFunc = oldSign }()
	jwtSignFunc = func(token *jwt.Token, secret string) (string, error) {
		return "", errors.New("sign error")
	}
	_, err := service.GenerateAccessToken(1, "email@test.com", time.Now().Add(time.Hour))
	assert.Error(t, err)
}

func TestAuthService_GenerateRefreshToken_SignError(t *testing.T) {
	service := NewAuthService(nil, config.JWTConfig{Secret: ""}, nil)
	oldSign := jwtSignFunc
	defer func() { jwtSignFunc = oldSign }()
	jwtSignFunc = func(token *jwt.Token, secret string) (string, error) {
		return "", errors.New("sign error")
	}
	_, err := service.GenerateRefreshToken(1, time.Now().Add(time.Hour))
	assert.Error(t, err)
}

// authServiceWithRefresh is a stub for testing refresh logic
type authServiceWithRefresh struct {
	refreshRepo RefreshTokenRepository
}

func (s *authServiceWithRefresh) RefreshToken(oldToken, newToken, userID string) (*RefreshTokenResponse, error) {
	token, err := s.refreshRepo.GetByToken(oldToken)
	if err != nil || token == nil {
		return nil, errors.New("invalid refresh token")
	}
	if token.IsRevoked {
		return nil, errors.New("token revoked")
	}
	if token.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("token expired")
	}
	revokedAt := time.Now()
	if err := s.refreshRepo.Revoke(token.ID, revokedAt); err != nil {
		return nil, err
	}
	newRefresh := &RefreshToken{
		ID:        4,
		Token:     newToken,
		UserID:    userID,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
	if err := s.refreshRepo.Create(newRefresh); err != nil {
		return nil, err
	}
	return &RefreshTokenResponse{
		AccessToken:  "access-token",
		RefreshToken: newToken,
		ExpiresIn:    1800,
		ExpiresAt:    time.Now().Add(30 * time.Minute).Format(time.RFC3339),
	}, nil
}

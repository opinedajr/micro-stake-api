package auth

import (
	"micro-stake/internal/config"
	"micro-stake/internal/user"

	"testing"

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
	service := NewAuthService(mockRepo, jwtConf)

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
	service := NewAuthService(mockRepo, jwtConf)

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
	service := NewAuthService(mockRepo, jwtConf)

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
	service := NewAuthService(mockRepo, jwtConf)

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
	service := NewAuthService(mockRepo, jwtConf)

	req := LoginRequest{
		Email:    "notfound@email.com",
		Password: "password123",
	}
	token, err := service.Login(req)
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestAuthService_GenerateJWT(t *testing.T) {
	jwtConf := config.JWTConfig{Secret: "test-secret", ExpirationHours: 24}
	service := NewAuthService(nil, jwtConf)
	token, err := service.GenerateJWT(42, "test@email.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

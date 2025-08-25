package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type mockAuthService struct {
	SignUpFunc               func(req SignUpRequest) (*SignUpResponse, error)
	LoginFunc                func(req LoginRequest) (*LoginResponse, error)
	GenerateAccessTokenFunc  func(userID int64, userEmail string, expiresAt time.Time) (string, error)
	GenerateRefreshTokenFunc func(userID int64, expiresAt time.Time) (string, error)
	RefreshTokenFunc         func(req RefreshTokenRequest) (*RefreshTokenResponse, error)
}

func (m *mockAuthService) SignUp(req SignUpRequest) (*SignUpResponse, error) {
	return m.SignUpFunc(req)
}
func (m *mockAuthService) Login(req LoginRequest) (*LoginResponse, error) {
	return m.LoginFunc(req)
}
func (m *mockAuthService) GenerateAccessToken(userID int64, userEmail string, expiresAt time.Time) (string, error) {
	if m.GenerateAccessTokenFunc != nil {
		return m.GenerateAccessTokenFunc(userID, userEmail, expiresAt)
	}
	return "", nil
}
func (m *mockAuthService) GenerateRefreshToken(userID int64, expiresAt time.Time) (string, error) {
	if m.GenerateRefreshTokenFunc != nil {
		return m.GenerateRefreshTokenFunc(userID, expiresAt)
	}
	return "", nil
}
func (m *mockAuthService) RefreshToken(req RefreshTokenRequest) (*RefreshTokenResponse, error) {
	if m.RefreshTokenFunc != nil {
		return m.RefreshTokenFunc(req)
	}
	return nil, nil
}

func TestAuthHandler_SignUp(t *testing.T) {
	mockService := &mockAuthService{
		SignUpFunc: func(req SignUpRequest) (*SignUpResponse, error) {
			return &SignUpResponse{
				ID:        1,
				Email:     req.Email,
				FirstName: req.FirstName,
				LastName:  req.LastName,
				CreatedAt: "2025-08-20T10:00:00Z",
			}, nil
		},
	}
	handler := NewAuthHandler(mockService)

	payload := SignUpRequest{
		Email:     "test@email.com",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.SignUp(w, req)
	resp := w.Result()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
}

func TestAuthHandler_Login(t *testing.T) {
	mockService := &mockAuthService{
		LoginFunc: func(req LoginRequest) (*LoginResponse, error) {
			return &LoginResponse{
				AccessToken:  "jwt-access-token",
				RefreshToken: "jwt-refresh-token",
				ExpiresIn:    1800,
				ExpiresAt:    time.Now().Add(30 * time.Minute).Format(time.RFC3339),
			}, nil
		},
	}
	handler := NewAuthHandler(mockService)

	payload := LoginRequest{
		Email:    "test@email.com",
		Password: "password123",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.Login(w, req)
	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAuthHandler_SignUp_InvalidPayload(t *testing.T) {
	mockService := &mockAuthService{
		SignUpFunc: func(req SignUpRequest) (*SignUpResponse, error) {
			return nil, nil
		},
	}
	handler := NewAuthHandler(mockService)

	body := []byte(`{"email": "test@email.com", "password": 123}`) // password como int, inválido
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.SignUp(w, req)
	resp := w.Result()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAuthHandler_SignUp_ServiceError(t *testing.T) {
	mockService := &mockAuthService{
		SignUpFunc: func(req SignUpRequest) (*SignUpResponse, error) {
			return nil, errors.New("user already exists")
		},
	}
	handler := NewAuthHandler(mockService)

	payload := SignUpRequest{
		Email:     "test@email.com",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.SignUp(w, req)
	resp := w.Result()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAuthHandler_Login_InvalidPayload(t *testing.T) {
	mockService := &mockAuthService{
		LoginFunc: func(req LoginRequest) (*LoginResponse, error) {
			return nil, nil
		},
	}
	handler := NewAuthHandler(mockService)

	body := []byte(`{"email": "test@email.com", "password": 123}`) // password como int, inválido
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.Login(w, req)
	resp := w.Result()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAuthHandler_Login_ServiceError(t *testing.T) {
	mockService := &mockAuthService{
		LoginFunc: func(req LoginRequest) (*LoginResponse, error) {
			return nil, errors.New("invalid credentials")
		},
	}
	handler := NewAuthHandler(mockService)

	payload := LoginRequest{
		Email:    "test@email.com",
		Password: "wrongpassword",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.Login(w, req)
	resp := w.Result()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAuthHandler_RefreshToken_Success(t *testing.T) {
	mockService := &mockAuthService{
		RefreshTokenFunc: func(req RefreshTokenRequest) (*RefreshTokenResponse, error) {
			return &RefreshTokenResponse{
				AccessToken:  "jwt-access-token",
				RefreshToken: "jwt-refresh-token",
				ExpiresIn:    1800,
				ExpiresAt:    time.Now().Add(30 * time.Minute).Format(time.RFC3339),
			}, nil
		},
	}
	handler := NewAuthHandler(mockService)

	payload := RefreshTokenRequest{
		RefreshToken: "valid-refresh-token",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.RefreshToken(w, req)
	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAuthHandler_RefreshToken_InvalidPayload(t *testing.T) {
	mockService := &mockAuthService{}
	handler := NewAuthHandler(mockService)

	body := []byte(`{"refresh_token": 123}`) // refresh_token como int, inválido
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.RefreshToken(w, req)
	resp := w.Result()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAuthHandler_RefreshToken_ServiceError(t *testing.T) {
	mockService := &mockAuthService{
		RefreshTokenFunc: func(req RefreshTokenRequest) (*RefreshTokenResponse, error) {
			return nil, errors.New("invalid refresh token")
		},
	}
	handler := NewAuthHandler(mockService)

	payload := RefreshTokenRequest{
		RefreshToken: "invalid-refresh-token",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.RefreshToken(w, req)
	resp := w.Result()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

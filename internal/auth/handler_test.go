package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockAuthService struct {
	SignUpFunc      func(req SignUpRequest) (*SignUpResponse, error)
	LoginFunc       func(req LoginRequest) (string, error)
	GenerateJWTFunc func(userID int64, userEmail string) (string, error)
}

func (m *mockAuthService) SignUp(req SignUpRequest) (*SignUpResponse, error) {
	return m.SignUpFunc(req)
}
func (m *mockAuthService) Login(req LoginRequest) (string, error) {
	return m.LoginFunc(req)
}
func (m *mockAuthService) GenerateJWT(userID int64, userEmail string) (string, error) {
	return m.GenerateJWTFunc(userID, userEmail)
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
		LoginFunc: func(req LoginRequest) (string, error) {
			return "jwt-token", nil
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
		LoginFunc: func(req LoginRequest) (string, error) {
			return "", nil
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
		LoginFunc: func(req LoginRequest) (string, error) {
			return "", errors.New("invalid credentials")
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

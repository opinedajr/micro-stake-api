package auth

import (
	"encoding/json"
	"net/http"
)

// AuthHandler handles authentication endpoints
type AuthHandler struct {
	service AuthService
}

func NewAuthHandler(service AuthService) *AuthHandler {
	return &AuthHandler{service: service}
}

// Handle user signup
func (h *AuthHandler) SignUp(w http.ResponseWriter, r *http.Request) {
	var req SignUpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error": map[string]interface{}{
				"code":    "INVALID_PAYLOAD",
				"message": "Invalid request body",
			},
		})
		return
	}
	user, err := h.service.SignUp(req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error": map[string]interface{}{
				"code":    "SIGNUP_ERROR",
				"message": err.Error(),
			},
		})
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    user,
		"message": "User created successfully",
	})
}

// Handle user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error": map[string]interface{}{
				"code":    "INVALID_PAYLOAD",
				"message": "Invalid request body",
			},
		})
		return
	}
	resp, err := h.service.Login(req)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error": map[string]interface{}{
				"code":    "LOGIN_ERROR",
				"message": err.Error(),
			},
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    resp,
		"message": "Login successful",
	})
}

// Handle refresh token
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error": map[string]interface{}{
				"code":    "INVALID_PAYLOAD",
				"message": "Invalid request body",
			},
		})
		return
	}
	// Preenche campos extras do request
	req.UserAgent = r.Header.Get("User-Agent")
	req.IPAddress = r.RemoteAddr
	req.DeviceID = r.Header.Get("X-Device-ID")
	resp, err := h.service.RefreshToken(req)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error": map[string]interface{}{
				"code":    "REFRESH_ERROR",
				"message": err.Error(),
			},
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    resp,
		"message": "Refresh successful",
	})
}

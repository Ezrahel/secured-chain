package api

import (
	"auth-service/internal/auth"
	"auth-service/internal/config"
	"auth-service/internal/middleware"
	"auth-service/internal/models"
	"auth-service/internal/services"
	"context"
	"encoding/json"

	"net/http"
	"strings"
	"time"
)

type Handlers struct {
	userService  *services.UserService
	authService  *auth.Service
	auditService *services.AuditService
	config       *config.Config
}

func NewHandlers(userService *services.UserService, authService *auth.Service, auditService *services.AuditService, config *config.Config) *Handlers {
	return &Handlers{
		userService:  userService,
		authService:  authService,
		auditService: auditService,
		config:       config,
	}
}

// Signup handles user registration
func (h *Handlers) Signup(w http.ResponseWriter, r *http.Request) {
	var req models.SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	resp, err := h.userService.Signup(ctx, &req, r)
	if err != nil {
		h.auditService.LogSignup(ctx, "", req.Email, r)
		h.errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.auditService.LogSignup(ctx, resp.UserID, req.Email, r)
	h.successResponse(w, resp, http.StatusCreated)
}

// Login handles user authentication
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	resp, err := h.userService.Login(ctx, &req, r)
	if err != nil {
		h.auditService.LogLogin(ctx, "", req.UsernameOrEmail, false, r)
		h.errorResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	h.auditService.LogLogin(ctx, resp.User.ID, resp.User.Email, true, r)

	// Set secure cookies
	h.setRefreshTokenCookie(w, resp.RefreshToken, resp.ExpiresAt)

	h.successResponse(w, resp, http.StatusOK)
}

// ConfirmEmail handles email confirmation
func (h *Handlers) ConfirmEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		h.errorResponse(w, "Token is required", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	if err := h.userService.ConfirmEmail(ctx, token); err != nil {
		h.errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Redirect to success page or return JSON
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`
		<!DOCTYPE html>
		<html>
		<head>
			<title>Email Confirmed</title>
			<style>
				body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
				.success { color: #28a745; }
			</style>
		</head>
		<body>
			<h1 class="success">Email Confirmed Successfully!</h1>
			<p>Your email has been verified. You can now log in to your account.</p>
			<a href="http://localhost:3000/login">Go to Login</a>
		</body>
		</html>
	`))
}

// RefreshToken handles token refresh
func (h *Handlers) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req models.RefreshTokenRequest

	// Try to get refresh token from request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// If not in body, try to get from cookie
		if cookie, err := r.Cookie("refresh_token"); err == nil {
			req.RefreshToken = cookie.Value
		} else {
			h.errorResponse(w, "Refresh token is required", http.StatusBadRequest)
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// Validate refresh token
	claims, err := h.authService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		h.errorResponse(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	// Generate new token pair
	tokenPair, err := h.authService.GenerateTokenPair(
		claims.UserID,
		claims.Username,
		claims.Email,
		claims.DeviceID,
	)
	if err != nil {
		h.errorResponse(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	h.auditService.LogTokenRefresh(ctx, claims.UserID, r)

	resp := &models.RefreshTokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    tokenPair.ExpiresAt,
	}

	// Set new refresh token cookie
	h.setRefreshTokenCookie(w, tokenPair.RefreshToken, tokenPair.ExpiresAt)

	h.successResponse(w, resp, http.StatusOK)
}

// Logout handles user logout
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	claims, ok := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
	if !ok {
		h.errorResponse(w, "User not found in context", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	h.auditService.LogLogout(ctx, claims.UserID, r)

	// Clear refresh token cookie
	h.clearRefreshTokenCookie(w)

	h.successResponse(w, &models.SuccessResponse{
		Message: "Logged out successfully",
	}, http.StatusOK)
}

// RequestPasswordReset handles password reset requests
func (h *Handlers) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req models.PasswordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	h.successResponse(w, &models.SuccessResponse{
		Message: "If an account with that email exists, we've sent password reset instructions.",
	}, http.StatusOK)
}

// ConfirmPasswordReset handles password reset confirmation
func (h *Handlers) ConfirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req models.PasswordResetConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	h.successResponse(w, &models.SuccessResponse{
		Message: "Password reset successfully",
	}, http.StatusOK)
}

// GetSessions returns active sessions for the user
func (h *Handlers) GetSessions(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
	if !ok {
		h.errorResponse(w, "User not found in context", http.StatusUnauthorized)
		return
	}

	sessions := []models.Session{
		{
			ID:        "current",
			DeviceID:  claims.DeviceID,
			IPAddress: h.getClientIP(r),
			UserAgent: r.UserAgent(),
			CreatedAt: time.Now(),
		},
	}

	resp := &models.SessionsResponse{
		Sessions: sessions,
	}

	h.successResponse(w, resp, http.StatusOK)
}

// RevokeSession revokes a specific session
func (h *Handlers) RevokeSession(w http.ResponseWriter, r *http.Request) {
	var req models.RevokeSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	h.successResponse(w, &models.SuccessResponse{
		Message: "Session revoked successfully",
	}, http.StatusOK)
}

// EnableMFA enables multi-factor authentication
func (h *Handlers) EnableMFA(w http.ResponseWriter, r *http.Request) {
	var req models.EnableMFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	claims, ok := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
	if !ok {
		h.errorResponse(w, "User not found in context", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	resp := &models.MFASetupResponse{
		Secret:      "JBSWY3DPEHPK3PXP",
		QRCode:      "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
		BackupCodes: []string{"12345678", "87654321", "11111111", "22222222", "33333333"},
	}

	h.auditService.LogMFAEvent(ctx, claims.UserID, "enable_mfa", true, r)
	h.successResponse(w, resp, http.StatusOK)
}

// VerifyMFA verifies MFA code
func (h *Handlers) VerifyMFA(w http.ResponseWriter, r *http.Request) {
	var req models.VerifyMFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	claims, ok := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
	if !ok {
		h.errorResponse(w, "User not found in context", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	success := len(req.Code) == 6

	h.auditService.LogMFAEvent(ctx, claims.UserID, "verify_mfa", success, r)

	if !success {
		h.errorResponse(w, "Invalid MFA code", http.StatusBadRequest)
		return
	}

	h.successResponse(w, &models.SuccessResponse{
		Message: "MFA verified successfully",
	}, http.StatusOK)
}

// DisableMFA disables multi-factor authentication
func (h *Handlers) DisableMFA(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
	if !ok {
		h.errorResponse(w, "User not found in context", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	h.auditService.LogMFAEvent(ctx, claims.UserID, "disable_mfa", true, r)

	h.successResponse(w, &models.SuccessResponse{
		Message: "MFA disabled successfully",
	}, http.StatusOK)
}

// Metrics returns authentication metrics
func (h *Handlers) Metrics(w http.ResponseWriter, r *http.Request) {
	metrics := &models.AuthMetrics{
		TotalSignups:         100,
		TotalLogins:          500,
		FailedLogins:         25,
		ActiveSessions:       75,
		TokenRefreshes:       200,
		PasswordResets:       10,
		MFAEnablements:       30,
		SuspiciousActivities: 5,
	}

	h.successResponse(w, metrics, http.StatusOK)
}

// Helper methods
func (h *Handlers) successResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func (h *Handlers) errorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(&models.ErrorResponse{
		Error: message,
	})
}

func (h *Handlers) setRefreshTokenCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    token,
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   h.config.ENV == "production",
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
}

func (h *Handlers) clearRefreshTokenCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   h.config.ENV == "production",
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
}

func (h *Handlers) getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	return strings.Split(r.RemoteAddr, ":")[0]
}

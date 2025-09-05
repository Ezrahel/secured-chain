package models

import (
	"time"
)

// Request models
type SignupRequest struct {
	Fullname        string `json:"fullname" validate:"required,min=1,max=100"`
	Username        string `json:"username" validate:"required,min=3,max=50,alphanum"`
	Email           string `json:"email" validate:"required,email"`
	Password        string `json:"password" validate:"required,min=12"`
	ConfirmPassword string `json:"confirm_password" validate:"required"`
	DeviceID        string `json:"device_id,omitempty"`
}

type LoginRequest struct {
	UsernameOrEmail string `json:"username_or_email" validate:"required"`
	Password        string `json:"password" validate:"required"`
	DeviceID        string `json:"device_id,omitempty"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type PasswordResetRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type PasswordResetConfirmRequest struct {
	Token           string `json:"token" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=12"`
	ConfirmPassword string `json:"confirm_password" validate:"required"`
}

type RevokeSessionRequest struct {
	SessionID string `json:"session_id" validate:"required"`
}

type EnableMFARequest struct {
	Password string `json:"password" validate:"required"`
}

type VerifyMFARequest struct {
	Code string `json:"code" validate:"required,len=6"`
}

// Response models
type SignupResponse struct {
	Message string `json:"message"`
	UserID  string `json:"user_id"`
}

type LoginResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	User         *UserInfo `json:"user"`
}

type RefreshTokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type UserInfo struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Fullname string `json:"fullname"`
}

type Session struct {
	ID                string    `json:"id"`
	DeviceID          string    `json:"device_id"`
	IPAddress         string    `json:"ip_address"`
	UserAgent         string    `json:"user_agent"`
	CreatedAt         time.Time `json:"created_at"`
	LastSeenAt        *time.Time `json:"last_seen_at"`
	DeviceFingerprint string    `json:"device_fingerprint"`
}

type SessionsResponse struct {
	Sessions []Session `json:"sessions"`
}

type MFASetupResponse struct {
	Secret      string   `json:"secret"`
	QRCode      string   `json:"qr_code"`
	BackupCodes []string `json:"backup_codes"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

type SuccessResponse struct {
	Message string `json:"message"`
}

// Audit log models
type AuditEvent struct {
	UserID    string                 `json:"user_id,omitempty"`
	EventType string                 `json:"event_type"`
	Payload   map[string]interface{} `json:"payload"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	Timestamp time.Time              `json:"timestamp"`
}

// Metrics models
type AuthMetrics struct {
	TotalSignups         int64 `json:"total_signups"`
	TotalLogins          int64 `json:"total_logins"`
	FailedLogins         int64 `json:"failed_logins"`
	ActiveSessions       int64 `json:"active_sessions"`
	TokenRefreshes       int64 `json:"token_refreshes"`
	PasswordResets       int64 `json:"password_resets"`
	MFAEnablements       int64 `json:"mfa_enablements"`
	SuspiciousActivities int64 `json:"suspicious_activities"`
}
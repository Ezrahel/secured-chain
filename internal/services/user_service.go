package services

import (
	"auth-service/internal/auth"
	"auth-service/internal/config"
	"auth-service/internal/crypto"
	"auth-service/internal/db"
	"auth-service/internal/mail"
	"auth-service/internal/models"
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
	// "github.com/google/uuid"
)

type UserService struct {
	queries       *db.Queries
	cryptoService *crypto.Service
	mailService   *mail.Service
	authService   *auth.Service
	config        *config.Config
}

func NewUserService(queries *db.Queries, cryptoService *crypto.Service, mailService *mail.Service, authService *auth.Service, config *config.Config) *UserService {
	return &UserService{
		queries:       queries,
		cryptoService: cryptoService,
		mailService:   mailService,
		authService:   authService,
		config:        config,
	}
}

func (s *UserService) Signup(ctx context.Context, req *models.SignupRequest, r *http.Request) (*models.SignupResponse, error) {
	// Validate input
	if err := s.validateSignupRequest(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Check if user already exists
	if _, err := s.queries.GetUserByEmail(ctx, req.Email); err == nil {
		return nil, fmt.Errorf("user with this email already exists")
	}

	if _, err := s.queries.GetUserByUsername(ctx, req.Username); err == nil {
		return nil, fmt.Errorf("user with this username already exists")
	}

	// Check password strength and breach status
	if err := s.validatePassword(ctx, req.Password); err != nil {
		return nil, fmt.Errorf("password validation failed: %w", err)
	}

	// Hash password
	passwordHash, err := s.authService.HashPassword(req.Password, s.config.Argon2)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user, err := s.queries.CreateUser(ctx, db.CreateUserParams{
		Fullname:     req.Fullname,
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: []byte(passwordHash),
		PasswordAlgo: "argon2id",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Generate email confirmation token
	token, err := s.authService.GenerateToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate confirmation token: %w", err)
	}

	tokenHash := s.authService.HashToken(token)
	expiresAt := time.Now().Add(s.config.EmailTokenExpiry)

	// Store email token
	_, err = s.queries.CreateEmailToken(ctx, db.CreateEmailTokenParams{
		UserID:    user.ID,
		TokenHash: tokenHash,
		Purpose:   "email_confirm",
		ExpiresAt: expiresAt,
		IpAddress: s.getClientIP(r),
		UserAgent: sql.NullString{String: r.UserAgent(), Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create email token: %w", err)
	}

	// Send confirmation email
	if err := s.mailService.SendConfirmationEmail(user.Email, user.Fullname, token, s.config.EmailConfirmURL); err != nil {
		return nil, fmt.Errorf("failed to send confirmation email: %w", err)
	}

	return &models.SignupResponse{
		Message: "Account created successfully. Please check your email to confirm your account.",
		UserID:  user.ID.String(),
	}, nil
}

func (s *UserService) Login(ctx context.Context, req *models.LoginRequest, r *http.Request) (*models.LoginResponse, error) {
	// Validate input
	if err := s.validateLoginRequest(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Get user by email or username
	user, err := s.queries.GetUserByEmailOrUsername(ctx, req.UsernameOrEmail)
	if err != nil {
		// Record failed login attempt
		s.recordFailedLoginAttempt(ctx, req.UsernameOrEmail, r)
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if user is locked
	if user.LockedUntil.Valid && user.LockedUntil.Time.After(time.Now()) {
		return nil, fmt.Errorf("account is locked until %v", user.LockedUntil.Time)
	}

	// Verify password
	valid, err := s.authService.VerifyPassword(req.Password, string(user.PasswordHash))
	if err != nil || !valid {
		// Increment failed login attempts
		s.queries.IncrementFailedLoginAttempts(ctx, user.ID)

		// Lock account if too many failed attempts
		if user.FailedLoginAttempts+1 >= int32(s.config.MaxLoginAttempts) {
			lockUntil := time.Now().Add(s.config.LockoutDuration)
			s.queries.LockUser(ctx, db.LockUserParams{
				ID:          user.ID,
				LockedUntil: sql.NullTime{Time: lockUntil, Valid: true},
			})
		}

		s.recordFailedLoginAttempt(ctx, req.UsernameOrEmail, r)
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if email is verified
	if !user.EmailVerified {
		return nil, fmt.Errorf("email not verified. Please check your email for confirmation link")
	}

	// Reset failed login attempts on successful login
	if user.FailedLoginAttempts > 0 {
		s.queries.UnlockUser(ctx, user.ID)
	}

	// Generate device fingerprint
	deviceFingerprint := s.generateDeviceFingerprint(r)

	// Generate tokens
	tokenPair, err := s.authService.GenerateTokenPair(
		user.ID.String(),
		user.Username,
		user.Email,
		req.DeviceID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Store refresh token
	refreshTokenHash := s.authService.HashToken(tokenPair.RefreshToken)
	_, err = s.queries.CreateAuthToken(ctx, db.CreateAuthTokenParams{
		UserID:            user.ID,
		TokenHash:         refreshTokenHash,
		DeviceID:          sql.NullString{String: req.DeviceID, Valid: req.DeviceID != ""},
		IpAddress:         s.getClientIP(r),
		UserAgent:         sql.NullString{String: r.UserAgent(), Valid: true},
		ExpiresAt:         time.Now().Add(time.Hour * 24 * 7), // 7 days
		DeviceFingerprint: sql.NullString{String: deviceFingerprint, Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &models.LoginResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    tokenPair.ExpiresAt,
		User: &models.UserInfo{
			ID:       user.ID.String(),
			Username: user.Username,
			Email:    user.Email,
			Fullname: user.Fullname,
		},
	}, nil
}

func (s *UserService) ConfirmEmail(ctx context.Context, token string) error {
	tokenHash := s.authService.HashToken(token)

	// Get email token
	emailToken, err := s.queries.GetEmailToken(ctx, tokenHash)
	if err != nil {
		return fmt.Errorf("invalid or expired token")
	}

	if emailToken.Purpose != "email_confirm" {
		return fmt.Errorf("invalid token purpose")
	}

	// Mark token as used
	if err := s.queries.UseEmailToken(ctx, emailToken.ID); err != nil {
		return fmt.Errorf("failed to use token: %w", err)
	}

	// Update user email verification status
	if err := s.queries.UpdateUserEmailVerified(ctx, emailToken.UserID); err != nil {
		return fmt.Errorf("failed to verify email: %w", err)
	}

	return nil
}

func (s *UserService) validateSignupRequest(req *models.SignupRequest) error {
	if req.Fullname == "" {
		return fmt.Errorf("fullname is required")
	}

	if req.Username == "" {
		return fmt.Errorf("username is required")
	}

	if len(req.Username) < 3 || len(req.Username) > 50 {
		return fmt.Errorf("username must be between 3 and 50 characters")
	}

	if req.Email == "" {
		return fmt.Errorf("email is required")
	}

	if !isValidEmail(req.Email) {
		return fmt.Errorf("invalid email format")
	}

	if req.Password != req.ConfirmPassword {
		return fmt.Errorf("passwords do not match")
	}

	return nil
}

func (s *UserService) validateLoginRequest(req *models.LoginRequest) error {
	if req.UsernameOrEmail == "" {
		return fmt.Errorf("username or email is required")
	}

	if req.Password == "" {
		return fmt.Errorf("password is required")
	}

	return nil
}

func (s *UserService) validatePassword(ctx context.Context, password string) error {
	if len(password) < s.config.PasswordMinLen {
		return fmt.Errorf("password must be at least %d characters long", s.config.PasswordMinLen)
	}

	// Check character classes
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
			hasSpecial = true
		}
	}

	classes := 0
	if hasUpper {
		classes++
	}
	if hasLower {
		classes++
	}
	if hasDigit {
		classes++
	}
	if hasSpecial {
		classes++
	}

	if classes < 3 {
		return fmt.Errorf("password must contain at least 3 different character classes (uppercase, lowercase, digits, special characters)")
	}

	// Check against HIBP if enabled
	if s.config.HIBP.Enabled {
		if breached, err := s.checkPasswordBreach(ctx, password); err == nil && breached {
			return fmt.Errorf("password has been found in data breaches and cannot be used")
		}
	}

	return nil
}

func (s *UserService) checkPasswordBreach(ctx context.Context, password string) (bool, error) {
	// Implementation of k-Anonymity HIBP check would go here
	// For now, return false (not breached)
	return false, nil
}

func (s *UserService) recordFailedLoginAttempt(ctx context.Context, usernameOrEmail string, r *http.Request) {
	s.queries.CreateFailedLoginAttempt(ctx, db.CreateFailedLoginAttemptParams{
		IpAddress:       s.getClientIP(r),
		UsernameOrEmail: usernameOrEmail,
		UserAgent:       sql.NullString{String: r.UserAgent(), Valid: true},
	})
}

func (s *UserService) getClientIP(r *http.Request) net.IP {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				return parsedIP
			}
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if parsedIP := net.ParseIP(xri); parsedIP != nil {
			return parsedIP
		}
	}

	// Use remote address
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

func (s *UserService) generateDeviceFingerprint(r *http.Request) string {
	// Simple device fingerprinting based on User-Agent and other headers
	fingerprint := fmt.Sprintf("%s|%s|%s",
		r.UserAgent(),
		r.Header.Get("Accept-Language"),
		r.Header.Get("Accept-Encoding"),
	)
	return fmt.Sprintf("%x", s.cryptoService.HashToken(fingerprint))
}

func isValidEmail(email string) bool {
	// Simple email validation
	return strings.Contains(email, "@") && strings.Contains(email, ".")
}

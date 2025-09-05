package middleware

import (
	"auth-service/internal/auth"
	"auth-service/internal/config"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"sync"

	// "strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"
)

type Manager struct {
	redisClient *redis.Client
	config      *config.Config
	authService *auth.Service
}

type contextKey string

const UserContextKey contextKey = "user"

func NewManager(redisClient *redis.Client, config *config.Config) *Manager {
	return &Manager{
		redisClient: redisClient,
		config:      config,
	}
}

func (m *Manager) SetAuthService(authService *auth.Service) {
	m.authService = authService
}

// RequestLogger logs HTTP requests with PII sanitization
func (m *Manager) RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response writer wrapper to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Process request
		next.ServeHTTP(wrapped, r)

		// Log request (sanitize sensitive data)
		duration := time.Since(start)
		log.Printf("method=%s path=%s status=%d duration=%v ip=%s user_agent=%s",
			r.Method,
			m.sanitizePath(r.URL.Path),
			wrapped.statusCode,
			duration,
			m.getClientIP(r),
			r.UserAgent(),
		)
	})
}

// Recovery middleware for panic recovery
func (m *Manager) Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic recovered: %v\n%s", err, debug.Stack())

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Internal server error",
				})
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// SecurityHeaders adds security headers
func (m *Manager) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HSTS
		w.Header().Set("Strict-Transport-Security", fmt.Sprintf("max-age=%d; includeSubDomains", m.config.HSTSMaxAge))

		// Content Security Policy
		w.Header().Set("Content-Security-Policy", m.config.CSPPolicy)

		// Other security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Remove server header
		w.Header().Set("Server", "")

		next.ServeHTTP(w, r)
	})
}

// RateLimit implements rate limiting
func (m *Manager) RateLimit(next http.Handler) http.Handler {
	limiters := make(map[string]*rate.Limiter)
	var mu sync.Mutex

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := m.getClientIP(r)

		mu.Lock()
		limiter, exists := limiters[clientIP]
		if !exists {
			if m.isAuthEndpoint(r.URL.Path) {
				limiter = rate.NewLimiter(rate.Every(time.Minute/time.Duration(m.config.AuthRateLimit.RequestsPerMinute)), m.config.AuthRateLimit.Burst)
			} else {
				limiter = rate.NewLimiter(rate.Every(time.Minute/time.Duration(m.config.RateLimit.RequestsPerMinute)), m.config.RateLimit.Burst)
			}
			limiters[clientIP] = limiter
		}
		mu.Unlock()

		if !limiter.Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Rate limit exceeded",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Authenticate middleware for protected routes
func (m *Manager) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			m.unauthorizedResponse(w, "Missing authorization header")
			return
		}

		// Extract token
		token, err := m.authService.ExtractTokenFromBearer(authHeader)
		if err != nil {
			m.unauthorizedResponse(w, "Invalid authorization header format")
			return
		}

		// Validate token
		claims, err := m.authService.ValidateAccessToken(token)
		if err != nil {
			m.unauthorizedResponse(w, "Invalid or expired token")
			return
		}

		// Add user info to context
		ctx := context.WithValue(r.Context(), UserContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// CSRF protection middleware
func (m *Manager) CSRFProtection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip CSRF for GET, HEAD, OPTIONS
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		// Check CSRF token
		csrfToken := r.Header.Get("X-CSRF-Token")
		if csrfToken == "" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "CSRF token required",
			})
			return
		}

		// Validate CSRF token (simplified implementation)
		// In production, use proper CSRF token validation
		if !m.validateCSRFToken(csrfToken, r) {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid CSRF token",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Helper functions
func (m *Manager) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Use remote address
	return strings.Split(r.RemoteAddr, ":")[0]
}

func (m *Manager) isAuthEndpoint(path string) bool {
	authPaths := []string{
		"/api/v1/login",
		"/api/v1/signup",
		"/api/v1/password-reset",
		"/api/v1/token/refresh",
	}

	for _, authPath := range authPaths {
		if strings.HasPrefix(path, authPath) {
			return true
		}
	}
	return false
}

func (m *Manager) sanitizePath(path string) string {
	// Remove sensitive parameters from logs
	if strings.Contains(path, "token=") {
		return strings.Split(path, "?")[0] + "?token=***"
	}
	return path
}

func (m *Manager) unauthorizedResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

func (m *Manager) validateCSRFToken(token string, r *http.Request) bool {
	// Simplified CSRF validation
	// In production, implement proper CSRF token validation with HMAC
	return len(token) > 10
}

// responseWriter wrapper to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

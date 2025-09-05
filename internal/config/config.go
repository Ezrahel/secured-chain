package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Server
	Host string
	Port string
	ENV  string

	// Database
	DatabaseURL string

	// Redis
	RedisURL      string
	RedisPassword string
	RedisDB       int

	// JWT
	JWT JWTConfig

	// SMTP
	SMTP SMTPConfig

	// Security
	EncryptionKey []byte
	Argon2        Argon2Config

	// Rate Limiting
	RateLimit     RateLimitConfig
	AuthRateLimit RateLimitConfig

	// Account Security
	MaxLoginAttempts int
	LockoutDuration  time.Duration
	PasswordMinLen   int

	// HIBP
	HIBP HIBPConfig

	// CORS
	CORS CORSConfig

	// Security Headers
	HSTSMaxAge int
	CSPPolicy  string

	// Logging
	LogLevel  string
	LogFormat string

	// Metrics
	MetricsEnabled bool
	MetricsPath    string

	// Email
	EmailTokenExpiry time.Duration
	ResetTokenExpiry time.Duration
	EmailConfirmURL  string
	EmailResetURL    string

	// MFA
	MFAIssuer  string
	MFAEnabled bool
}

type JWTConfig struct {
	AccessSecret   []byte
	RefreshSecret  []byte
	AccessExpiry   time.Duration
	RefreshExpiry  time.Duration
}

type SMTPConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	From     string
	Timeout  time.Duration
}

type Argon2Config struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

type RateLimitConfig struct {
	RequestsPerMinute int
	Burst             int
}

type HIBPConfig struct {
	APIURL  string
	Timeout time.Duration
	Enabled bool
}

type CORSConfig struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
}

func Load() (*Config, error) {
	cfg := &Config{
		Host: getEnv("HOST", "localhost"),
		Port: getEnv("PORT", "8080"),
		ENV:  getEnv("ENV", "development"),

		DatabaseURL: getEnv("DATABASE_URL", ""),

		RedisURL:      getEnv("REDIS_URL", "redis://localhost:6379/0"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		RedisDB:       getEnvInt("REDIS_DB", 0),

		JWT: JWTConfig{
			AccessSecret:  []byte(getEnv("JWT_ACCESS_SECRET", "")),
			RefreshSecret: []byte(getEnv("JWT_REFRESH_SECRET", "")),
			AccessExpiry:  getEnvDuration("JWT_ACCESS_EXPIRY", "10m"),
			RefreshExpiry: getEnvDuration("JWT_REFRESH_EXPIRY", "7d"),
		},

		SMTP: SMTPConfig{
			Host:     getEnv("SMTP_HOST", "smtp.gmail.com"),
			Port:     getEnvInt("SMTP_PORT", 587),
			User:     getEnv("SMTP_USER", ""),
			Password: getEnv("SMTP_PASSWORD", ""),
			From:     getEnv("SMTP_FROM", ""),
			Timeout:  getEnvDuration("SMTP_TIMEOUT", "10s"),
		},

		EncryptionKey: []byte(getEnv("ENCRYPTION_KEY", "")),

		Argon2: Argon2Config{
			Memory:      uint32(getEnvInt("ARGON2_MEMORY", 65536)),
			Iterations:  uint32(getEnvInt("ARGON2_ITERATIONS", 3)),
			Parallelism: uint8(getEnvInt("ARGON2_PARALLELISM", 2)),
			SaltLength:  uint32(getEnvInt("ARGON2_SALT_LENGTH", 16)),
			KeyLength:   uint32(getEnvInt("ARGON2_KEY_LENGTH", 32)),
		},

		RateLimit: RateLimitConfig{
			RequestsPerMinute: getEnvInt("RATE_LIMIT_REQUESTS_PER_MINUTE", 60),
			Burst:             getEnvInt("RATE_LIMIT_BURST", 10),
		},

		AuthRateLimit: RateLimitConfig{
			RequestsPerMinute: getEnvInt("AUTH_RATE_LIMIT_REQUESTS_PER_MINUTE", 10),
			Burst:             getEnvInt("AUTH_RATE_LIMIT_BURST", 3),
		},

		MaxLoginAttempts: getEnvInt("MAX_LOGIN_ATTEMPTS", 5),
		LockoutDuration:  getEnvDuration("LOCKOUT_DURATION", "15m"),
		PasswordMinLen:   getEnvInt("PASSWORD_MIN_LENGTH", 12),

		HIBP: HIBPConfig{
			APIURL:  getEnv("HIBP_API_URL", "https://api.pwnedpasswords.com/range"),
			Timeout: getEnvDuration("HIBP_TIMEOUT", "5s"),
			Enabled: getEnvBool("HIBP_ENABLED", true),
		},

		CORS: CORSConfig{
			AllowedOrigins: strings.Split(getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:3000"), ","),
			AllowedMethods: strings.Split(getEnv("CORS_ALLOWED_METHODS", "GET,POST,PUT,DELETE,OPTIONS"), ","),
			AllowedHeaders: strings.Split(getEnv("CORS_ALLOWED_HEADERS", "Content-Type,Authorization,X-Requested-With,X-Device-ID"), ","),
		},

		HSTSMaxAge: getEnvInt("HSTS_MAX_AGE", 31536000),
		CSPPolicy:  getEnv("CSP_POLICY", "default-src 'self'"),

		LogLevel:  getEnv("LOG_LEVEL", "info"),
		LogFormat: getEnv("LOG_FORMAT", "json"),

		MetricsEnabled: getEnvBool("METRICS_ENABLED", true),
		MetricsPath:    getEnv("METRICS_PATH", "/metrics"),

		EmailTokenExpiry: getEnvDuration("EMAIL_TOKEN_EXPIRY", "24h"),
		ResetTokenExpiry: getEnvDuration("RESET_TOKEN_EXPIRY", "1h"),
		EmailConfirmURL:  getEnv("EMAIL_CONFIRM_URL", "http://localhost:8080/api/v1/confirm-email"),
		EmailResetURL:    getEnv("EMAIL_RESET_URL", "http://localhost:3000/reset-password"),

		MFAIssuer:  getEnv("MFA_ISSUER", "AuthService"),
		MFAEnabled: getEnvBool("MFA_ENABLED", true),
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) validate() error {
	if c.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}

	if len(c.JWT.AccessSecret) < 32 {
		return fmt.Errorf("JWT_ACCESS_SECRET must be at least 32 bytes")
	}

	if len(c.JWT.RefreshSecret) < 32 {
		return fmt.Errorf("JWT_REFRESH_SECRET must be at least 32 bytes")
	}

	if len(c.EncryptionKey) != 32 {
		return fmt.Errorf("ENCRYPTION_KEY must be exactly 32 bytes")
	}

	if c.SMTP.User == "" || c.SMTP.Password == "" {
		return fmt.Errorf("SMTP credentials are required")
	}

	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue string) time.Duration {
	value := getEnv(key, defaultValue)
	if duration, err := time.ParseDuration(value); err == nil {
		return duration
	}
	// Fallback to default if parsing fails
	if duration, err := time.ParseDuration(defaultValue); err == nil {
		return duration
	}
	return time.Minute // Ultimate fallback
}
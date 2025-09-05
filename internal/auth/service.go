package auth

import (
	"auth-service/internal/config"
	"auth-service/internal/crypto"
)

type Service struct {
	jwtService    *JWTService
	cryptoService *crypto.Service
}

func NewService(jwtConfig config.JWTConfig, cryptoService *crypto.Service) *Service {
	jwtService := NewJWTService(
		jwtConfig.AccessSecret,
		jwtConfig.RefreshSecret,
		jwtConfig.AccessExpiry,
		jwtConfig.RefreshExpiry,
	)

	return &Service{
		jwtService:    jwtService,
		cryptoService: cryptoService,
	}
}

func (s *Service) GenerateTokenPair(userID, username, email, deviceID string) (*TokenPair, error) {
	return s.jwtService.GenerateTokenPair(userID, username, email, deviceID)
}

func (s *Service) ValidateAccessToken(token string) (*Claims, error) {
	return s.jwtService.ValidateAccessToken(token)
}

func (s *Service) ValidateRefreshToken(token string) (*Claims, error) {
	return s.jwtService.ValidateRefreshToken(token)
}

func (s *Service) ExtractTokenFromBearer(authHeader string) (string, error) {
	return s.jwtService.ExtractTokenFromBearer(authHeader)
}

func (s *Service) HashPassword(password string, argon2Config config.Argon2Config) (string, error) {
	return s.cryptoService.HashPassword(
		password,
		argon2Config.Memory,
		argon2Config.Iterations,
		argon2Config.Parallelism,
		argon2Config.SaltLength,
		argon2Config.KeyLength,
	)
}

func (s *Service) VerifyPassword(password, hash string) (bool, error) {
	return s.cryptoService.VerifyPassword(password, hash)
}

func (s *Service) GenerateToken(length int) (string, error) {
	return s.cryptoService.GenerateToken(length)
}

func (s *Service) HashToken(token string) []byte {
	return s.cryptoService.HashToken(token)
}
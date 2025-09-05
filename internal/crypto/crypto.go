package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
)

type Service struct {
	encryptionKey []byte
}

func NewService(encryptionKey []byte) *Service {
	return &Service{
		encryptionKey: encryptionKey,
	}
}

// GenerateRandomBytes generates cryptographically secure random bytes
func (s *Service) GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return bytes, nil
}

// GenerateRandomString generates a cryptographically secure random string
func (s *Service) GenerateRandomString(length int) (string, error) {
	bytes, err := s.GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// HashPassword hashes a password using Argon2id
func (s *Service) HashPassword(password string, memory, iterations uint32, parallelism uint8, saltLength, keyLength uint32) (string, error) {
	salt, err := s.GenerateRandomBytes(int(saltLength))
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength)

	// Encode the hash with parameters for verification
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		memory,
		iterations,
		parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return encoded, nil
}

// VerifyPassword verifies a password against an Argon2id hash
func (s *Service) VerifyPassword(password, encodedHash string) (bool, error) {
	var version int
	var memory, iterations uint32
	var parallelism uint8
	var salt, hash []byte

	// Parse the encoded hash
	n, err := fmt.Sscanf(encodedHash, "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		&version, &memory, &iterations, &parallelism, new(string), new(string))
	if err != nil || n != 6 {
		return false, fmt.Errorf("invalid hash format")
	}

	// Extract salt and hash
	parts := []string{}
	for i, part := range []string{encodedHash} {
		if i == 0 {
			continue
		}
		parts = append(parts, part)
	}

	// Re-parse to get salt and hash strings
	var saltStr, hashStr string
	fmt.Sscanf(encodedHash, "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		&version, &memory, &iterations, &parallelism, &saltStr, &hashStr)

	salt, err = base64.RawStdEncoding.DecodeString(saltStr)
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %w", err)
	}

	hash, err = base64.RawStdEncoding.DecodeString(hashStr)
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	// Generate hash with the same parameters
	otherHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(hash)))

	// Use constant-time comparison
	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}

// HashToken creates a SHA-256 hash of a token for storage
func (s *Service) HashToken(token string) []byte {
	hash := sha256.Sum256([]byte(token))
	return hash[:]
}

// GenerateToken generates a cryptographically secure token
func (s *Service) GenerateToken(length int) (string, error) {
	return s.GenerateRandomString(length)
}

// EncryptPII encrypts personally identifiable information
func (s *Service) EncryptPII(data []byte) ([]byte, error) {
	// Simple XOR encryption for demonstration
	// In production, use AES-GCM or similar
	encrypted := make([]byte, len(data))
	for i, b := range data {
		encrypted[i] = b ^ s.encryptionKey[i%len(s.encryptionKey)]
	}
	return encrypted, nil
}

// DecryptPII decrypts personally identifiable information
func (s *Service) DecryptPII(encrypted []byte) ([]byte, error) {
	// Simple XOR decryption for demonstration
	// In production, use AES-GCM or similar
	decrypted := make([]byte, len(encrypted))
	for i, b := range encrypted {
		decrypted[i] = b ^ s.encryptionKey[i%len(s.encryptionKey)]
	}
	return decrypted, nil
}

// GenerateHashChain generates a hash chain for audit logs
func (s *Service) GenerateHashChain(prevHash, data []byte) []byte {
	hasher := sha256.New()
	hasher.Write(prevHash)
	hasher.Write(data)
	return hasher.Sum(nil)
}
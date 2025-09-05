# Production-Ready Go Authentication Service

A comprehensive authentication service built with Go, PostgreSQL, and FAANG-level security controls.

## Features

### Authentication & Security
- JWT access tokens (10min expiry) + rotating refresh tokens
- Device binding with IP fingerprinting
- Argon2id password hashing with breach checking (HIBP)
- Optional MFA (TOTP + WebAuthn scaffold)
- Email confirmation via Google SMTP
- Account lockout with progressive delays
- Comprehensive audit logging with hash chains

### API Endpoints
- `POST /api/v1/signup` - User registration
- `GET /api/v1/confirm-email` - Email confirmation
- `POST /api/v1/login` - User authentication
- `POST /api/v1/token/refresh` - Token rotation
- `POST /api/v1/logout` - Session termination
- `POST /api/v1/password-reset/request` - Password reset request
- `POST /api/v1/password-reset/confirm` - Password reset confirmation
- `GET /api/v1/sessions` - List active sessions
- `POST /api/v1/sessions/revoke` - Revoke session
- `POST /api/v1/mfa/*` - MFA endpoints

### Security Controls
- Rate limiting (IP + user based)
- CSRF protection with SameSite cookies
- Input validation and SQL injection prevention
- Secure headers (HSTS, CSP, etc.)
- PII encryption with envelope encryption
- Comprehensive monitoring and alerting

## Quick Start

### Prerequisites
- Go 1.22+
- PostgreSQL 15+
- Docker & Docker Compose

### Local Development

1. **Clone and setup environment**
```bash
cp .env.example .env
# Edit .env with your configuration
```

2. **Start services**
```bash
make dev-up    # Start PostgreSQL + MailHog
make migrate   # Run database migrations
make run       # Start the API server
```

3. **Access services**
- API: http://localhost:8080
- Web UI: http://localhost:3000
- MailHog: http://localhost:8025

### Testing

```bash
make test           # Run unit tests
make test-integration # Run integration tests
make test-security  # Run security tests
make load-test      # Run k6 load tests
```

### Build & Deploy

```bash
make build          # Build binary
make docker-build   # Build Docker image
make deploy         # Deploy to staging
```

## Configuration

See `.env.example` for all configuration options.

### Google SMTP Setup

1. Enable 2-factor authentication on your Google account
2. Generate an App Password: Account Settings > Security > App passwords
3. Use your email and app password in .env:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM="YourApp <no-reply@yourdomain.com>"
```

## Architecture

```
cmd/
├── server/          # Main application entry point
└── migrate/         # Database migration tool

internal/
├── api/            # HTTP handlers and routes
├── auth/           # Authentication logic
├── crypto/         # Cryptographic utilities
├── db/             # Database layer (sqlc generated)
├── mail/           # Email service
├── middleware/     # HTTP middleware
├── models/         # Data models
└── services/       # Business logic

migrations/         # SQL migration files
tests/             # Integration and security tests
web/               # Frontend testing interface
docs/              # API documentation
```

## Security

This service implements FAANG-level security controls:

- **Password Security**: Argon2id hashing, breach checking, strong policies
- **Token Security**: Short-lived JWTs, rotating refresh tokens, device binding
- **API Security**: Rate limiting, input validation, OWASP compliance
- **Audit**: Comprehensive logging with tamper-evident hash chains
- **Encryption**: PII encryption at rest, secure key management

See `docs/SECURITY.md` for detailed security documentation.

## Development

### Generate Code
```bash
make generate      # Generate sqlc code
make docs          # Generate API docs
```

### Database Operations
```bash
make migrate-up    # Apply migrations
make migrate-down  # Rollback migrations
make migrate-reset # Reset database
```

### Code Quality
```bash
make lint          # Run linters
make fmt           # Format code
make vet           # Run go vet
make security      # Run security analysis
```

## Monitoring

The service exposes metrics at `/metrics` (Prometheus format) including:
- Authentication success/failure rates
- Token rotation events
- Suspicious activity detection
- Performance metrics

## License

MIT License - see LICENSE file for details.
.PHONY: help build run test clean dev-up dev-down migrate migrate-up migrate-down migrate-reset generate lint fmt vet security docker-build docker-run load-test

# Default target
help:
	@echo "Available targets:"
	@echo "  build          - Build the application"
	@echo "  run            - Run the application"
	@echo "  test           - Run unit tests"
	@echo "  test-integration - Run integration tests"
	@echo "  test-security  - Run security tests"
	@echo "  clean          - Clean build artifacts"
	@echo "  dev-up         - Start development services (PostgreSQL, Redis, MailHog)"
	@echo "  dev-down       - Stop development services"
	@echo "  migrate        - Run database migrations"
	@echo "  migrate-up     - Apply all migrations"
	@echo "  migrate-down   - Rollback one migration"
	@echo "  migrate-reset  - Reset database"
	@echo "  generate       - Generate code (sqlc, swagger)"
	@echo "  lint           - Run linters"
	@echo "  fmt            - Format code"
	@echo "  vet            - Run go vet"
	@echo "  security       - Run security analysis"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-run     - Run Docker container"
	@echo "  load-test      - Run k6 load tests"

# Build
build:
	@echo "Building application..."
	@go build -o bin/server cmd/server/main.go
	@go build -o bin/migrate cmd/migrate/main.go

# Run
run:
	@echo "Starting server..."
	@go run cmd/server/main.go

# Test
test:
	@echo "Running unit tests..."
	@go test -v -race -cover ./internal/...

test-integration:
	@echo "Running integration tests..."
	@go test -v -race -tags=integration ./tests/...

test-security:
	@echo "Running security tests..."
	@go test -v -race -tags=security ./tests/security/...

# Clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bin/
	@go clean

# Development services
dev-up:
	@echo "Starting development services..."
	@docker-compose -f docker-compose.dev.yml up -d

dev-down:
	@echo "Stopping development services..."
	@docker-compose -f docker-compose.dev.yml down

# Database migrations
migrate: migrate-up

migrate-up:
	@echo "Applying database migrations..."
	@go run cmd/migrate/main.go up

migrate-down:
	@echo "Rolling back one migration..."
	@go run cmd/migrate/main.go down

migrate-reset:
	@echo "Resetting database..."
	@go run cmd/migrate/main.go reset

# Code generation
generate:
	@echo "Generating code..."
	@sqlc generate
	@go generate ./...

# Code quality
lint:
	@echo "Running linters..."
	@golangci-lint run

fmt:
	@echo "Formatting code..."
	@go fmt ./...

vet:
	@echo "Running go vet..."
	@go vet ./...

security:
	@echo "Running security analysis..."
	@gosec ./...

# Docker
docker-build:
	@echo "Building Docker image..."
	@docker build -t auth-service:latest .

docker-run:
	@echo "Running Docker container..."
	@docker run -p 8080:8080 --env-file .env auth-service:latest

# Load testing
load-test:
	@echo "Running k6 load tests..."
	@k6 run tests/load/auth_load_test.js

# Install tools
install-tools:
	@echo "Installing development tools..."
	@go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
	@go install github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.54.2
	@go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
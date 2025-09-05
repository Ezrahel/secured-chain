-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "citext";

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fullname TEXT NOT NULL,
    username TEXT UNIQUE NOT NULL,
    email CITEXT UNIQUE NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    password_hash BYTEA NOT NULL,
    password_algo TEXT NOT NULL DEFAULT 'argon2id',
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    disabled BOOLEAN DEFAULT FALSE,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ NULL,
    metadata JSONB NULL
);

-- Indexes for users
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_users_disabled ON users(disabled);

-- Auth tokens table (for refresh tokens)
CREATE TABLE auth_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    device_id TEXT,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    rotate_count INTEGER DEFAULT 0,
    last_seen_at TIMESTAMPTZ NULL,
    device_fingerprint TEXT
);

-- Indexes for auth_tokens
CREATE INDEX idx_auth_tokens_user_id ON auth_tokens(user_id);
CREATE INDEX idx_auth_tokens_token_hash ON auth_tokens(token_hash);
CREATE INDEX idx_auth_tokens_expires_at ON auth_tokens(expires_at);
CREATE INDEX idx_auth_tokens_revoked_at ON auth_tokens(revoked_at);
CREATE INDEX idx_auth_tokens_device_id ON auth_tokens(device_id);

-- Email tokens table (for email confirmation and password reset)
CREATE TABLE email_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('email_confirm', 'password_reset')),
    created_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ NULL,
    ip_address INET,
    user_agent TEXT
);

-- Indexes for email_tokens
CREATE INDEX idx_email_tokens_user_id ON email_tokens(user_id);
CREATE INDEX idx_email_tokens_token_hash ON email_tokens(token_hash);
CREATE INDEX idx_email_tokens_purpose ON email_tokens(purpose);
CREATE INDEX idx_email_tokens_expires_at ON email_tokens(expires_at);

-- Auth audit logs table
CREATE TABLE auth_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    event_payload JSONB NOT NULL,
    occurred_at TIMESTAMPTZ DEFAULT now(),
    ip_address INET,
    user_agent TEXT,
    prev_hash BYTEA NULL,
    hash BYTEA NOT NULL
);

-- Indexes for audit logs
CREATE INDEX idx_auth_audit_logs_user_id ON auth_audit_logs(user_id);
CREATE INDEX idx_auth_audit_logs_event_type ON auth_audit_logs(event_type);
CREATE INDEX idx_auth_audit_logs_occurred_at ON auth_audit_logs(occurred_at);

-- MFA secrets table
CREATE TABLE mfa_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_encrypted BYTEA NOT NULL,
    backup_codes_encrypted BYTEA NULL,
    enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT now(),
    last_used_at TIMESTAMPTZ NULL
);

-- Indexes for MFA
CREATE INDEX idx_mfa_secrets_user_id ON mfa_secrets(user_id);
CREATE INDEX idx_mfa_secrets_enabled ON mfa_secrets(enabled);

-- WebAuthn credentials table (scaffold for future WebAuthn implementation)
CREATE TABLE webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    attestation_type TEXT NOT NULL,
    aaguid UUID NULL,
    sign_count BIGINT DEFAULT 0,
    clone_warning BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT now(),
    last_used_at TIMESTAMPTZ NULL,
    name TEXT NOT NULL
);

-- Indexes for WebAuthn
CREATE INDEX idx_webauthn_credentials_user_id ON webauthn_credentials(user_id);
CREATE INDEX idx_webauthn_credentials_credential_id ON webauthn_credentials(credential_id);

-- Failed login attempts tracking
CREATE TABLE failed_login_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address INET NOT NULL,
    username_or_email TEXT NOT NULL,
    attempted_at TIMESTAMPTZ DEFAULT now(),
    user_agent TEXT
);

-- Indexes for failed login attempts
CREATE INDEX idx_failed_login_attempts_ip ON failed_login_attempts(ip_address);
CREATE INDEX idx_failed_login_attempts_username ON failed_login_attempts(username_or_email);
CREATE INDEX idx_failed_login_attempts_attempted_at ON failed_login_attempts(attempted_at);

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply updated_at trigger to users table
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Create function to clean expired tokens
CREATE OR REPLACE FUNCTION clean_expired_tokens()
RETURNS void AS $$
BEGIN
    -- Clean expired auth tokens
    DELETE FROM auth_tokens WHERE expires_at < now();
    
    -- Clean expired email tokens
    DELETE FROM email_tokens WHERE expires_at < now();
    
    -- Clean old failed login attempts (older than 24 hours)
    DELETE FROM failed_login_attempts WHERE attempted_at < now() - INTERVAL '24 hours';
END;
$$ LANGUAGE plpgsql;

-- Create index for efficient cleanup
CREATE INDEX idx_auth_tokens_expired ON auth_tokens(expires_at) WHERE revoked_at IS NULL;
CREATE INDEX idx_email_tokens_expired ON email_tokens(expires_at) WHERE used_at IS NULL;
-- Drop functions
DROP FUNCTION IF EXISTS clean_expired_tokens();
DROP FUNCTION IF EXISTS update_updated_at_column() CASCADE;

-- Drop tables in reverse order
DROP TABLE IF EXISTS failed_login_attempts;
DROP TABLE IF EXISTS webauthn_credentials;
DROP TABLE IF EXISTS mfa_secrets;
DROP TABLE IF EXISTS auth_audit_logs;
DROP TABLE IF EXISTS email_tokens;
DROP TABLE IF EXISTS auth_tokens;
DROP TABLE IF EXISTS users;

-- Drop extensions
DROP EXTENSION IF EXISTS "citext";
DROP EXTENSION IF EXISTS "uuid-ossp";
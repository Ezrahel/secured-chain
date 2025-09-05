-- name: CreateUser :one
INSERT INTO users (
    fullname, username, email, password_hash, password_algo
) VALUES (
    $1, $2, $3, $4, $5
) RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1 AND disabled = false;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1 AND disabled = false;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = $1 AND disabled = false;

-- name: GetUserByEmailOrUsername :one
SELECT * FROM users 
WHERE (email = $1 OR username = $1) AND disabled = false;

-- name: UpdateUserEmailVerified :exec
UPDATE users SET email_verified = true, updated_at = now() 
WHERE id = $1;

-- name: UpdateUserPassword :exec
UPDATE users SET 
    password_hash = $2, 
    password_algo = $3, 
    failed_login_attempts = 0,
    locked_until = NULL,
    updated_at = now()
WHERE id = $1;

-- name: IncrementFailedLoginAttempts :exec
UPDATE users SET 
    failed_login_attempts = failed_login_attempts + 1,
    updated_at = now()
WHERE id = $1;

-- name: LockUser :exec
UPDATE users SET 
    locked_until = $2,
    updated_at = now()
WHERE id = $1;

-- name: UnlockUser :exec
UPDATE users SET 
    failed_login_attempts = 0,
    locked_until = NULL,
    updated_at = now()
WHERE id = $1;

-- name: DisableUser :exec
UPDATE users SET disabled = true, updated_at = now() WHERE id = $1;

-- name: EnableUser :exec
UPDATE users SET disabled = false, updated_at = now() WHERE id = $1;

-- name: UpdateUserMetadata :exec
UPDATE users SET metadata = $2, updated_at = now() WHERE id = $1;
-- name: CreateAuthToken :one
INSERT INTO auth_tokens (
    user_id, token_hash, device_id, ip_address, user_agent, expires_at, device_fingerprint
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
) RETURNING *;

-- name: GetAuthToken :one
SELECT * FROM auth_tokens 
WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now();

-- name: GetUserAuthTokens :many
SELECT * FROM auth_tokens 
WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
ORDER BY created_at DESC;

-- name: UpdateAuthTokenLastSeen :exec
UPDATE auth_tokens SET 
    last_seen_at = now(),
    rotate_count = rotate_count + 1
WHERE id = $1;

-- name: RevokeAuthToken :exec
UPDATE auth_tokens SET revoked_at = now() WHERE id = $1;

-- name: RevokeUserAuthTokens :exec
UPDATE auth_tokens SET revoked_at = now() 
WHERE user_id = $1 AND revoked_at IS NULL;

-- name: RevokeAuthTokenByHash :exec
UPDATE auth_tokens SET revoked_at = now() WHERE token_hash = $1;

-- name: CleanExpiredAuthTokens :exec
DELETE FROM auth_tokens WHERE expires_at < now();

-- name: GetAuthTokenByDeviceID :one
SELECT * FROM auth_tokens 
WHERE user_id = $1 AND device_id = $2 AND revoked_at IS NULL AND expires_at > now()
ORDER BY created_at DESC LIMIT 1;
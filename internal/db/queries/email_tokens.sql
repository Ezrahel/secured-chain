-- name: CreateEmailToken :one
INSERT INTO email_tokens (
    user_id, token_hash, purpose, expires_at, ip_address, user_agent
) VALUES (
    $1, $2, $3, $4, $5, $6
) RETURNING *;

-- name: GetEmailToken :one
SELECT * FROM email_tokens 
WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now();

-- name: UseEmailToken :exec
UPDATE email_tokens SET used_at = now() WHERE id = $1;

-- name: CleanExpiredEmailTokens :exec
DELETE FROM email_tokens WHERE expires_at < now();

-- name: RevokeUserEmailTokens :exec
UPDATE email_tokens SET used_at = now() 
WHERE user_id = $1 AND purpose = $2 AND used_at IS NULL;
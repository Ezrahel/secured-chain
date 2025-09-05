-- name: CreateMFASecret :one
INSERT INTO mfa_secrets (
    user_id, secret_encrypted, backup_codes_encrypted
) VALUES (
    $1, $2, $3
) RETURNING *;

-- name: GetMFASecret :one
SELECT * FROM mfa_secrets WHERE user_id = $1;

-- name: EnableMFA :exec
UPDATE mfa_secrets SET enabled = true WHERE user_id = $1;

-- name: DisableMFA :exec
UPDATE mfa_secrets SET enabled = false WHERE user_id = $1;

-- name: UpdateMFALastUsed :exec
UPDATE mfa_secrets SET last_used_at = now() WHERE user_id = $1;

-- name: DeleteMFASecret :exec
DELETE FROM mfa_secrets WHERE user_id = $1;
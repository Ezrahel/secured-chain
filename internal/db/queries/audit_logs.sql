-- name: CreateAuditLog :one
INSERT INTO auth_audit_logs (
    user_id, event_type, event_payload, ip_address, user_agent, prev_hash, hash
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
) RETURNING *;

-- name: GetLastAuditLogHash :one
SELECT hash FROM auth_audit_logs ORDER BY id DESC LIMIT 1;

-- name: GetUserAuditLogs :many
SELECT * FROM auth_audit_logs 
WHERE user_id = $1 
ORDER BY occurred_at DESC 
LIMIT $2 OFFSET $3;

-- name: GetAuditLogsByEventType :many
SELECT * FROM auth_audit_logs 
WHERE event_type = $1 AND occurred_at >= $2
ORDER BY occurred_at DESC 
LIMIT $3 OFFSET $4;
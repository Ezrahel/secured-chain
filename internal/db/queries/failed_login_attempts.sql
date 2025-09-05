-- name: CreateFailedLoginAttempt :exec
INSERT INTO failed_login_attempts (
    ip_address, username_or_email, user_agent
) VALUES (
    $1, $2, $3
);

-- name: GetFailedLoginAttemptsByIP :one
SELECT COUNT(*) FROM failed_login_attempts 
WHERE ip_address = $1 AND attempted_at > $2;

-- name: GetFailedLoginAttemptsByUsername :one
SELECT COUNT(*) FROM failed_login_attempts 
WHERE username_or_email = $1 AND attempted_at > $2;

-- name: CleanOldFailedLoginAttempts :exec
DELETE FROM failed_login_attempts WHERE attempted_at < $1;
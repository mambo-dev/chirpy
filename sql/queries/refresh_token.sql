-- name: CreateRefreshToken :one
INSERT INTO refresh_token (token, user_id, expires_at)
VALUES (
    $1,
    $2,
    $3
)
RETURNING *;



-- name: GetRefreshToken :one
SELECT * FROM refresh_token WHERE token = $1;

-- name: RevokeRefreshToken :exec
UPDATE refresh_token
SET revoked_at = NOW(), updated_at = NOW()
WHERE token = $1;
-- name: CreateRefreshToken :one
INSERT INTO refresh_token (token, user_id)
VALUES (
    $1,
    $2
)
RETURNING *;
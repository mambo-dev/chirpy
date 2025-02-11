-- name: CreateUser :one
INSERT INTO users(email, hashed_password)
VALUES( 
    $1,
    $2
)
RETURNING id, email,is_chirpy_red, created_at, updated_at;

-- name: DeleteUsers :exec
DELETE FROM users;


-- name: GetUserByEmail :one
SELECT  * FROM users 
WHERE email = $1;


-- name: UpdateUserCredentials :one
UPDATE users
SET hashed_password = $1, email = $2, updated_at = NOW()
WHERE id = $3
RETURNING id,email, is_chirpy_red,created_at, updated_at;

-- name: UpdateUserAccount :exec
UPDATE users 
SET updated_at = NOW(), is_chirpy_red = TRUE
WHERE id = $1;
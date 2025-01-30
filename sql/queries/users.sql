-- name: CreateUser :one
INSERT INTO users(email, hashed_password)
VALUES( 
    $1,
    $2
)
RETURNING id, email, created_at, updated_at;

-- name: DeleteUsers :exec
DELETE FROM users;


-- name: GetUserByEmail :one
SELECT  * FROM users 
WHERE email = $1;

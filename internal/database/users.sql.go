// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: users.sql

package database

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const createUser = `-- name: CreateUser :one
INSERT INTO users(email, hashed_password)
VALUES( 
    $1,
    $2
)
RETURNING id, email,is_chirpy_red, created_at, updated_at
`

type CreateUserParams struct {
	Email          string
	HashedPassword string
}

type CreateUserRow struct {
	ID          uuid.UUID
	Email       string
	IsChirpyRed bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (CreateUserRow, error) {
	row := q.db.QueryRowContext(ctx, createUser, arg.Email, arg.HashedPassword)
	var i CreateUserRow
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.IsChirpyRed,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const deleteUsers = `-- name: DeleteUsers :exec
DELETE FROM users
`

func (q *Queries) DeleteUsers(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteUsers)
	return err
}

const getUserByEmail = `-- name: GetUserByEmail :one
SELECT  id, created_at, updated_at, email, hashed_password, is_chirpy_red FROM users 
WHERE email = $1
`

func (q *Queries) GetUserByEmail(ctx context.Context, email string) (User, error) {
	row := q.db.QueryRowContext(ctx, getUserByEmail, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}

const updateUserAccount = `-- name: UpdateUserAccount :exec
UPDATE users 
SET updated_at = NOW(), is_chirpy_red = TRUE
WHERE id = $1
`

func (q *Queries) UpdateUserAccount(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.ExecContext(ctx, updateUserAccount, id)
	return err
}

const updateUserCredentials = `-- name: UpdateUserCredentials :one
UPDATE users
SET hashed_password = $1, email = $2, updated_at = NOW()
WHERE id = $3
RETURNING id,email, is_chirpy_red,created_at, updated_at
`

type UpdateUserCredentialsParams struct {
	HashedPassword string
	Email          string
	ID             uuid.UUID
}

type UpdateUserCredentialsRow struct {
	ID          uuid.UUID
	Email       string
	IsChirpyRed bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (q *Queries) UpdateUserCredentials(ctx context.Context, arg UpdateUserCredentialsParams) (UpdateUserCredentialsRow, error) {
	row := q.db.QueryRowContext(ctx, updateUserCredentials, arg.HashedPassword, arg.Email, arg.ID)
	var i UpdateUserCredentialsRow
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.IsChirpyRed,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

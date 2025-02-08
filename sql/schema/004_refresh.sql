-- +goose Up
CREATE TABLE refresh_token(
    token TEXT  PRIMARY KEY,
    created_at  TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP,
    user_id UUID,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES  users(id) ON DELETE CASCADE
);

-- +goose Down
DROP TABLE refresh_token;
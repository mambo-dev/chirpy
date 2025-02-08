package auth_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mambo-dev/chirpy/internal/auth"
)

func TestHashingFunction(t *testing.T) {
	password := "1234"
	hash, err := auth.HashPassword(password)
	if hash == "" || err != nil {
		t.Fatalf("Hashing for password %v failed with; %v", password, err.Error())
	}
}

func TestHashPass(t *testing.T) {
	password := "1234"
	hash, err := auth.HashPassword(password)
	if hash == "" || err != nil {
		t.Fatalf("Hashing for password %v failed with; %v", password, err.Error())
	}

	compError := auth.CheckPasswordHash("1234", hash)

	if compError != nil {
		t.Fatalf("Comparing %v and hashed password failed with: %v", password, err.Error())
	}
}

func TestJWTfunction(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "this is secret"

	duration, err := time.ParseDuration("1m")
	if err != nil {
		t.Fatal("could not pass the duration")
	}
	token, err := auth.MakeJWT(userID, tokenSecret, duration)

	if err != nil {
		t.Fatalf("ERROR: Failed to make jwt ->%v\n", err.Error())
	}

	validUserID, err := auth.ValidateJWT(token, tokenSecret)

	if err != nil {
		t.Fatalf("ERROR: Failed to validate jwt ->%v\n", err.Error())

	}

	if userID != validUserID {
		t.Fatalf("ERROR: user ids did not match ->%v\n", err.Error())
	}

}

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expected    string
		expectError bool
	}{
		{
			name:        "Valid bearer token",
			headers:     http.Header{"Authorization": []string{"Bearer secrettoken"}},
			expected:    "secrettoken",
			expectError: false,
		},
		{
			name:        "Missing header",
			headers:     http.Header{},
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := auth.GetBearerToken(tt.headers)
			if err != nil && !tt.expectError {
				t.Errorf("Expected error: %v, got: %v", tt.expectError, err)
			}

			if token != tt.expected {
				t.Errorf("Expected token: %s, got: %s", tt.expected, token)
			}
		})
	}

}

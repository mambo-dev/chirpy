package auth_test

import (
	"testing"

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

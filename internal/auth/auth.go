package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)

	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func CheckPasswordHash(password string, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

	if err != nil {
		return err
	}

	return nil
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "Chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Subject:   userID.String(),
	})

	signedToken, err := token.SignedString([]byte(tokenSecret))

	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	claims, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {

		return []byte(tokenSecret), nil
	})

	if err != nil {
		fmt.Printf("ERROR: Invalid token received ->%v\n", err.Error())
		return uuid.New(), err
	}

	userID, err := claims.Claims.GetSubject()

	if err != nil {
		fmt.Printf("ERROR: Failed to get user id from subject ->%v\n", err.Error())
		return uuid.New(), err
	}

	userUUID, err := uuid.Parse(userID)

	if err != nil {
		fmt.Printf("ERROR:%v\n", err.Error())
		return uuid.New(), err
	}

	return userUUID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")

	if len(authHeader) < 1 {
		return "", errors.New("did not get authorization header")
	}

	authString := strings.Split(authHeader, " ")[1]

	return authString, nil

}

func MakeRefreshToken() (string, error) {
	bt := make([]byte, 32)

	_, err := rand.Read(bt)

	if err != nil {
		return "", err
	}

	hexString := hex.EncodeToString(bt)

	return hexString, nil
}

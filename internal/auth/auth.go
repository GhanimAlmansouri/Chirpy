package auth

import (
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func GetAPIKey(headers http.Header) (string, error) {

	authHeaader := headers.Get("Authorization")
	if !strings.HasPrefix(authHeaader, "ApiKey ") {

		return "", fmt.Errorf("Invalid Authorization header format")
	}

	APIKey := strings.TrimSpace(strings.TrimPrefix(authHeaader, "ApiKey"))
	if APIKey == "" {
		return "", fmt.Errorf("API key is missing")
	}
	return APIKey, nil

}

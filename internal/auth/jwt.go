package auth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn).UTC()),
		Subject:   userID.String()}) //Creates a new claim called token, the claim contains information that verifies the user.

	signedToken, err := token.SignedString([]byte(tokenSecret)) // the claim is signed in order to verify it by the server. It will later be used to verify the user requests.
	if err != nil {
		return "", err
	}
	return signedToken, nil

}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	var claims jwt.RegisteredClaims

	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(tokenSecret), nil
	})

	if err != nil {
		return uuid.Nil, err
	}
	if !token.Valid {
		return uuid.Nil, fmt.Errorf("invalid token")
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, err
	}

	return userID, nil

}

func GetBearerToken(headers http.Header) (string, error) {
	var bearerToken string

	bearerToken = headers.Get("Authorization")
	if bearerToken == "" {
		return "", fmt.Errorf("No token found")
	}

	if !strings.HasPrefix(bearerToken, "Bearer") {
		return "", fmt.Errorf("malformed authorization header")
	}

	bearerToken = strings.TrimSpace(bearerToken[7:])
	return bearerToken, nil

}

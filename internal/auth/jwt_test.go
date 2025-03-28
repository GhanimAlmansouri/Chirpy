package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestJWTBasic(t *testing.T) {
	// A very basic test to ensure the environment works
	userID := uuid.New()
	token, err := MakeJWT(userID, "secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("Token is empty")
	}
}

func TestJWTCreationAndValidation(t *testing.T) {
	// Generate a random user ID
	userID := uuid.New()

	// Define a test secret
	secret := "test-secret"

	// Create a JWT that expires in 1 hour
	token, err := MakeJWT(userID, secret, time.Hour)
	if err != nil {
		t.Fatalf("Error creating JWT: %v", err)
	}

	// Validate the JWT
	extractedID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("Error validating JWT: %v", err)
	}

	// Check if the extracted ID matches the original ID
	if extractedID != userID {
		t.Fatalf("Expected user ID %v, got %v", userID, extractedID)
	}
}

func TestJWTExpiration(t *testing.T) {
	// Generate a random user ID
	userID := uuid.New()

	// Define a test secret
	secret := "test-secret"

	// Create a JWT that expires in -1 hour (already expired)
	token, err := MakeJWT(userID, secret, -time.Hour)
	if err != nil {
		t.Fatalf("Error creating JWT: %v", err)
	}

	// Try to validate the expired JWT
	_, err = ValidateJWT(token, secret)

	// We EXPECT an error here since the token is expired
	if err == nil {
		t.Fatal("Expected error for expired token, but got nil")
	}

	// Optional: Check if the error is related to expiration
	// The exact error message might vary depending on the JWT library version
	t.Logf("Got expected error for expired token: %v", err)
}

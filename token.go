package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/chirpy/internal/auth"
	"github.com/chirpy/internal/database"
)

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, r *http.Request) {

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	refreshToken := strings.TrimPrefix(authHeader, "Bearer ")

	tokenData, err := cfg.DB.GetRefreshToken(r.Context(), refreshToken)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}
	if tokenData.ExpiresAt.Before(time.Now()) {
		http.Error(w, "Refresh token has expired", http.StatusUnauthorized)
		return
	}
	if tokenData.RevokedAt.Valid {
		http.Error(w, "Refresh token has been revoked", http.StatusUnauthorized)
		return
	}

	newToken, err := auth.MakeJWT(tokenData.UserID, cfg.jwtSecret, time.Hour)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	response := map[string]string{"token": newToken}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(response)

}

func (cfg *apiConfig) revokeHandler(w http.ResponseWriter, r *http.Request) {

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	refreshToken := strings.TrimPrefix(authHeader, "Bearer ")

	tokenData, err := cfg.DB.GetRefreshToken(r.Context(), refreshToken)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	if tokenData.ExpiresAt.Before(time.Now()) {
		http.Error(w, "Refresh token has expired", http.StatusUnauthorized)
		return
	}

	if tokenData.RevokedAt.Valid {
		http.Error(w, "Refresh token has already been revoked", http.StatusUnauthorized)
		return
	}

	type UpdateRefreshTokenParams struct {
		Token     string
		RevokedAt time.Time
		UpdatedAt time.Time
	}

	now := time.Now()
	params := database.UpdateRefreshTokenParams{Token: tokenData.Token, RevokedAt: sql.NullTime{Time: now, Valid: true}, UpdatedAt: now}
	err = cfg.DB.UpdateRefreshToken(r.Context(), params)
	if err != nil {
		http.Error(w, "Could not update the refresh token", http.StatusUnauthorized)
		return

	}

	w.WriteHeader(204)

}

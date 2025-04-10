package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/chirpy/internal/auth"
	"github.com/chirpy/internal/database"
	"github.com/google/uuid"
)

func (cfg *apiConfig) createUserHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	user, err := cfg.DB.CreateUser(r.Context(), database.CreateUserParams{Email: params.Email, HashedPassword: hashedPassword})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	responseUser := User{
		ID:            user.ID,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
		Email:         user.Email,
		Is_Chirpy_Red: user.IsChirpyRed.Bool,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(responseUser)
}

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, r *http.Request) {

	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	params := parameters{}
	decoder := json.NewDecoder(r.Body)

	err := decoder.Decode(&params)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	user, err := cfg.DB.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if auth.CheckPasswordHash(params.Password, user.HashedPassword) != nil {

		http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
		return
	}

	token, err := auth.MakeJWT(user.ID, cfg.jwtSecret, time.Duration(3600)*time.Second)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}
	type refreshTokenParams struct {
		Token     string    `json:"token"`
		UserID    uuid.UUID `json:"user_id"`
		ExpiresAt time.Time `json:"expires_at"`
	}

	now := time.Now()
	expires_at := now.Add(time.Duration(60) * 24 * time.Hour)

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		http.Error(w, "Failed to create refresh token", http.StatusInternalServerError)
		return
	}

	refreshTokenParam := database.AddRefreshTokenParams{Token: refreshToken, UserID: user.ID, ExpiresAt: expires_at}

	err = cfg.DB.AddRefreshToken(r.Context(), refreshTokenParam)

	if err != nil {
		fmt.Println("Error adding refresh to database:", err)
		http.Error(w, "Cannot add refresh token", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	responseUser := User{
		ID:            user.ID,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
		Email:         user.Email,
		Token:         token,
		Refresh_token: refreshToken,
		Is_Chirpy_Red: user.IsChirpyRed.Bool,
	}

	json.NewEncoder(w).Encode(responseUser)
}

func (cfg *apiConfig) updateUserHandler(w http.ResponseWriter, r *http.Request) {

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	refreshToken := strings.TrimPrefix(authHeader, "Bearer ")

	userID, err := auth.ValidateJWT(refreshToken, cfg.jwtSecret)

	if err != nil {
		http.Error(w, "Invalid Token", http.StatusUnauthorized)
		return
	}

	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	params := parameters{}
	decoder := json.NewDecoder(r.Body)

	err = decoder.Decode(&params)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	user, err := cfg.DB.GetUserByID(r.Context(), userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}
	if userID != user.ID {
		http.Error(w, "Forbidden: you may only update your own account", http.StatusForbidden)
		return
	}

	hash, err := auth.HashPassword(params.Password)
	if err != nil {
		http.Error(w, "Could not hash password", http.StatusInternalServerError)
		return
	}

	type UpdateUserParams struct {
		ID             uuid.UUID
		HashedPassword string
		Email          string
	}

	err = cfg.DB.UpdateUser(r.Context(), database.UpdateUserParams{ID: user.ID, HashedPassword: hash, Email: params.Email})
	if err != nil {

		http.Error(w, "User could not be updated", http.StatusInternalServerError)
		return

	}
	updatedUser := map[string]string{"email": params.Email}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(updatedUser)
}

func (cfg *apiConfig) updateUserRedHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "ApiKey ") {

		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		http.Error(w, "Error retrieving key", http.StatusUnauthorized)
		return
	}

	if apiKey != cfg.polkaSecret {

		http.Error(w, "Unauthorized action", http.StatusUnauthorized)
		return
	}

	type webhookData struct {
		UserID uuid.UUID `json:"user_id"`
	}
	type webhookBody struct {
		Event string      `json:"event"`
		Data  webhookData `json:"data"`
	}

	decoder := json.NewDecoder(r.Body)
	var payload webhookBody
	err = decoder.Decode(&payload)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	if payload.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	err = cfg.DB.UpgradeUserRed(r.Context(), payload.Data.UserID)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

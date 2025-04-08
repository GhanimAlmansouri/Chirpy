package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/chirpy/internal/auth"
	"github.com/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type User struct {
	ID            uuid.UUID `json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Email         string    `json:"email"`
	Token         string    `json:"token"`
	Refresh_token string    `json:"refresh_token"`
	Is_Chirpy_Red bool      `json:"is_chirpy_red"`
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func (api *apiConfig) hits(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	htmlResponse := fmt.Sprintf("<html>\n  <body>\n    <h1>Welcome, Chirpy Admin</h1>\n    <p>Chirpy has been visited %d times!</p>\n  </body>\n</html>", api.fileServerHits.Load())
	w.Write([]byte(htmlResponse))
}

type apiConfig struct {
	platform       string
	DB             *database.Queries
	fileServerHits atomic.Int32
	jwtSecret      string
	polkaSecret    string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileServerHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

type Chirp struct {
	ID         uuid.UUID `json:"id"`
	Created_at time.Time `json:"created_at"`
	Updated_at time.Time `json:"updated_at"`
	Body       string    `json:"body"`
	User_id    uuid.UUID `json:"user_id"`
}

func validateAndCleanChirp(body string) (string, error) {
	profane := []string{"kerfuffle", "sharbert", "fornax"}

	if len(body) > 140 {

		return "", fmt.Errorf("{\"error\":\"Chirp is too long\"}")
	}

	message := strings.Split(body, " ")
	for i, word := range message {
		for _, profanity := range profane {
			if profanity == strings.ToLower(word) {
				message[i] = "****"
			}
		}
	}
	return strings.Join(message, " "), nil
}

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

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	err := cfg.DB.DeleteAllUsers(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (cfg *apiConfig) chirpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Method not allowed"))
		return
	}

	decoder := json.NewDecoder(r.Body)

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, "Missing or invalid token", http.StatusUnauthorized)
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	var params struct {
		Body string `json:"body"`
	}

	err = decoder.Decode(&params)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	cleanedBody, err := validateAndCleanChirp(params.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	dbParams := database.CreateChirpParams{
		Body:   cleanedBody,
		UserID: userID,
	}

	chirp, err := cfg.DB.CreateChirp(r.Context(), dbParams)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"Error": "Failed to create chirp"})
		return
	}

	responseChirp := Chirp{
		ID:         chirp.ID,
		Created_at: chirp.CreatedAt,
		Updated_at: chirp.UpdatedAt,
		Body:       chirp.Body,
		User_id:    chirp.UserID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(responseChirp)

}

func (cfg *apiConfig) returnChirpsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	author := r.URL.Query().Get("author_id")
	sortType := r.URL.Query().Get("sort")

	responsechirps := []Chirp{}

	if author != "" {
		authorID, err := uuid.Parse(author)
		if err != nil {
			http.Error(w, "Could not parse author_id to uuid", http.StatusInternalServerError)
			return

		}
		authorChirps, err := cfg.DB.GetAllChirpsByID(r.Context(), authorID)

		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "could not retrieve chirps"})
			return
		}

		for _, dbchirp := range authorChirps {
			if dbchirp.UserID == authorID {
				responsechirps = append(responsechirps, Chirp{
					ID:         dbchirp.ID,
					Created_at: dbchirp.CreatedAt,
					Updated_at: dbchirp.UpdatedAt,
					Body:       dbchirp.Body,
					User_id:    dbchirp.UserID,
				})
			}
		}
	} else {
		chirps, err := cfg.DB.GetAllChirps(r.Context())

		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "could not retrieve chirps"})
			return
		}
		for _, dbchirp := range chirps {
			responsechirps = append(responsechirps, Chirp{
				ID:         dbchirp.ID,
				Created_at: dbchirp.CreatedAt,
				Updated_at: dbchirp.UpdatedAt,
				Body:       dbchirp.Body,
				User_id:    dbchirp.UserID,
			})
		}
	}

	if sortType == "desc" {
		sort.Slice(responsechirps, func(i, j int) bool {
			return responsechirps[i].Created_at.After(responsechirps[j].Created_at)
		})
	} else {
		sort.Slice(responsechirps, func(i, j int) bool {
			return responsechirps[i].Created_at.Before(responsechirps[j].Created_at)
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(responsechirps)

}

func (cfg *apiConfig) getChirpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	chirpIDstr := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(chirpIDstr)
	if err != nil {
		http.Error(w, "Invalid Chirp ID", http.StatusBadRequest)
		return
	}
	chirp, err := cfg.DB.GetChirp(r.Context(), chirpID)
	if err != nil {
		http.Error(w, "Chirp not found", http.StatusNotFound)
		return
	}

	responseChirp := Chirp{
		ID:         chirp.ID,
		Created_at: chirp.CreatedAt,
		Updated_at: chirp.UpdatedAt,
		Body:       chirp.Body,
		User_id:    chirp.UserID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(responseChirp)
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

func (cfg *apiConfig) deleteChirpHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Invalid Authentication header format ", http.StatusUnauthorized)
		return
	}

	refreshToken := strings.TrimPrefix(authHeader, "Bearer ")

	userID, err := auth.ValidateJWT(refreshToken, cfg.jwtSecret)

	if err != nil {
		http.Error(w, "Invalid Token", http.StatusUnauthorized)
		return
	}

	chirpIDstr := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(chirpIDstr)
	if err != nil {
		http.Error(w, "Invalid chirp ID", http.StatusBadRequest)
		return
	}

	chirp, err := cfg.DB.GetChirp(r.Context(), chirpID)
	if err != nil {
		http.Error(w, "Chirp not found", http.StatusNotFound)
		return
	}
	if chirp.UserID != userID {
		http.Error(w, "Unauthorized user for this chirp", http.StatusForbidden)
		return
	}

	err = cfg.DB.DeleteChirp(r.Context(), chirp.ID)

	if err != nil {
		http.Error(w, "Could not delete chirp", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)

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

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	dbURL := os.Getenv("DB_URL")
	jwtSecret := os.Getenv("JWT_SECRET")
	polkaSecret := os.Getenv("POLKA_KEY")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET not found in environment")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Println(err)
	}

	dbQueries := database.New(db)
	mux := http.NewServeMux()
	var server http.Server
	server.Addr = "localhost:8080"
	server.Handler = mux

	apiCfg := apiConfig{
		DB:          dbQueries,
		platform:    os.Getenv("PLATFORM"),
		jwtSecret:   jwtSecret,
		polkaSecret: polkaSecret,
	}

	mux.HandleFunc("GET /api/healthz", healthHandler)
	mux.HandleFunc("GET /admin/metrics", apiCfg.hits)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)
	mux.HandleFunc("POST /api/users", apiCfg.createUserHandler)
	mux.HandleFunc("POST /api/chirps", apiCfg.chirpHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.returnChirpsHandler)
	mux.HandleFunc("POST /api/login", apiCfg.loginHandler)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpHandler)
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshHandler)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeHandler)
	mux.HandleFunc("PUT /api/users", apiCfg.updateUserHandler)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirpHandler)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.updateUserRedHandler)
	mux.Handle("/app/", http.StripPrefix("/app/", apiCfg.middlewareMetricsInc(http.FileServer(http.Dir(".")))))
	log.Fatal(server.ListenAndServe())

}

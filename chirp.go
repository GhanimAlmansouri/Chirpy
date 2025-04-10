package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/chirpy/internal/auth"
	"github.com/chirpy/internal/database"
	"github.com/google/uuid"
)

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

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
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
		Email string `json:"email"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	user, err := cfg.DB.CreateUser(r.Context(), params.Email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	responseUser := User{
		ID:        user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
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
	var params struct {
		Body   string    `json:"body"`
		UserID uuid.UUID `json:"user_id"`
	}
	err := decoder.Decode(&params)
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
		UserID: params.UserID,
	}

	chirp, err := cfg.DB.CreateChirp(r.Context(), dbParams)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"Error": "Failed to create chirp"})
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
	chirps, err := cfg.DB.GetAllChirps(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "could not retrieve chirps"})
		return
	}
	responsechirps := []Chirp{}
	for _, dbchirp := range chirps {
		responsechirps = append(responsechirps, Chirp{
			ID:         dbchirp.ID,
			Created_at: dbchirp.CreatedAt,
			Updated_at: dbchirp.UpdatedAt,
			Body:       dbchirp.Body,
			User_id:    dbchirp.UserID,
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

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Println(err)
	}
	dbQueries := database.New(db)
	mux := http.NewServeMux()
	var server http.Server
	server.Addr = "localhost:8080"
	server.Handler = mux
	apiCfg := apiConfig{DB: dbQueries, platform: os.Getenv("PLATFORM")}
	mux.HandleFunc("GET /api/healthz", healthHandler)
	mux.HandleFunc("GET /admin/metrics", apiCfg.hits)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)
	mux.HandleFunc("POST /api/users", apiCfg.createUserHandler)
	mux.HandleFunc("POST /api/chirps", apiCfg.chirpHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.returnChirpsHandler)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpHandler)
	mux.Handle("/app/", http.StripPrefix("/app/", apiCfg.middlewareMetricsInc(http.FileServer(http.Dir(".")))))
	log.Fatal(server.ListenAndServe())

}

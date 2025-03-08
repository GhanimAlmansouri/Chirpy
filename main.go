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

	"github.com/chirpy/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

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

func (api *apiConfig) reset(w http.ResponseWriter, r *http.Request) {
	api.fileServerHits.Store(0)
	w.Write([]byte("Hits Reset Successfully"))
}

type apiConfig struct {
	DB             *database.Queries
	fileServerHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileServerHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func validateChirp(w http.ResponseWriter, r *http.Request) {

	type chirp struct {
		Body string `json:"body"`
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("Something went wrong"))
		return
	}

	decoder := json.NewDecoder(r.Body)
	params := chirp{}
	profane := []string{"kerfuffle", "sharbert", "fornax"}
	err := decoder.Decode(&params)
	w.Header().Set("Content-Type", "application/json")

	if err != nil {
		error := fmt.Sprintf("{\"error\":\"%s\"}", err)
		w.Write([]byte(error))
	}

	if len(params.Body) > 140 {
		w.WriteHeader(400)
		error := fmt.Sprintf("{\"error\":\"Chirp is too long\"}")
		w.Write([]byte(error))
	} else {
		w.WriteHeader(200)
		message := strings.Split(params.Body, " ")
		for i, word := range message {

			for _, profanity := range profane {
				if profanity == strings.ToLower(word) {
					message[i] = "****"
				}

			}
		}
		cleanMessage := strings.Join(message, " ")
		cleanBody := fmt.Sprintf("{\"cleaned_body\": \"%s\"}", cleanMessage)
		w.Write([]byte(cleanBody))
	}

}

func main() {
	godotenv.Load()
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
	apiCfg := apiConfig{DB: dbQueries}
	mux.HandleFunc("GET /api/healthz", healthHandler)
	mux.HandleFunc("GET /admin/metrics", apiCfg.hits)
	mux.HandleFunc("POST /admin/reset", apiCfg.reset)
	mux.HandleFunc("POST /api/validate_chirp", validateChirp)
	mux.Handle("/app/", http.StripPrefix("/app/", apiCfg.middlewareMetricsInc(http.FileServer(http.Dir(".")))))
	log.Fatal(server.ListenAndServe())

}

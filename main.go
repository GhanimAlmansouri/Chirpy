package main

import (
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func (api *apiConfig) hits(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	x := fmt.Sprintf("Hits: %d", api.fileServerHits.Load())
	w.Write([]byte(x))
}

func (api *apiConfig) reset(w http.ResponseWriter, r *http.Request) {
	api.fileServerHits.Store(0)
	w.Write([]byte("Hits Reset Successfully"))
}

type apiConfig struct {
	fileServerHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileServerHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func main() {
	mux := http.NewServeMux()
	var server http.Server
	server.Addr = "localhost:8080"
	server.Handler = mux
	var apiCfg apiConfig
	mux.HandleFunc("GET /healthz", healthHandler)
	mux.HandleFunc("GET /metrics", apiCfg.hits)
	mux.HandleFunc("POST /reset", apiCfg.reset)
	mux.Handle("/app/", http.StripPrefix("/app/", apiCfg.middlewareMetricsInc(http.FileServer(http.Dir(".")))))
	log.Fatal(server.ListenAndServe())

}

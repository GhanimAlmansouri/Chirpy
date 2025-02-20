package main

import (
	"log"
	"net/http"
)

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func main() {
	mux := http.NewServeMux()
	var server http.Server
	server.Addr = "localhost:8080"
	server.Handler = mux

	mux.HandleFunc("/healthz", healthHandler)
	mux.Handle("/app/", http.StripPrefix("/app/", http.FileServer(http.Dir("."))))
	log.Fatal(server.ListenAndServe())

}

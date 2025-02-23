package main

import (
	"log"
	"net/http"
	"github.com/gorilla/mux"
)

func main() {
	LoadBlockchain()

	r := setupRouter()
	
	log.Println("🚀 Quantum-Safe Blockchain running on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

func setupRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/blockchain", GetBlockchain).Methods("GET")
	return r
}

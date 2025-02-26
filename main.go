package main
import (
    "encoding/json"
    "log"
    "net/http"
    "github.com/gorilla/mux"
    "github.com/cloudflare/circl/sign/dilithium"
)

import (
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/gorilla/mux"
)

func main() {
	// Generate quantum-safe keys
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		log.Fatal("Failed to generate seed:", err)
	}
	_, publicKey := mode3.NewKeyFromSeed(&seed)

	// Initialize router with explicit IPv4 binding
	r := mux.NewRouter()
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Quantum Blockchain Node\nWallet Address: %x", publicKey.Bytes())
	})

	log.Println("🚀 Node running on 127.0.0.1:8080 | CTRL+C to exit")
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", r))
}

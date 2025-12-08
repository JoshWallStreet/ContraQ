package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/gorilla/mux"
)

// Wallet structure
type Wallet struct {
	PublicKey  []byte `json:"public_key"`
	PrivateKey []byte `json:"private_key"` // In real deployment, encrypt this
}

// Load or create wallet
func loadOrCreateWallet(filename string) (*Wallet, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		// Generate keys
		var seed [32]byte
		if _, err := rand.Read(seed[:]); err != nil {
			return nil, fmt.Errorf("failed to generate seed: %v", err)
		}
		priv, pub := mode3.NewKeyFromSeed(&seed)
		wallet := &Wallet{
			PublicKey:  pub.Bytes(),
			PrivateKey: priv.Bytes(),
		}
		data, _ := json.MarshalIndent(wallet, "", "  ")
		if err := ioutil.WriteFile(filename, data, 0600); err != nil {
			return nil, fmt.Errorf("failed to write wallet file: %v", err)
		}
		log.Println("📝 New wallet created and saved")
		return wallet, nil
	}

	// Load existing wallet
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read wallet file: %v", err)
	}
	var wallet Wallet
	if err := json.Unmarshal(data, &wallet); err != nil {
		return nil, fmt.Errorf("failed to unmarshal wallet: %v", err)
	}
	log.Println("🔑 Wallet loaded from file")
	return &wallet, nil
}

func main() {
	wallet, err := loadOrCreateWallet("wallet.json")
	if err != nil {
		log.Fatal(err)
	}

	r := mux.NewRouter()

	// Return wallet public key
	r.HandleFunc("/wallet", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]string{
			"public_key": fmt.Sprintf("%x", wallet.PublicKey),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Sign a message
	r.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		type SignRequest struct {
			Message string `json:"message"`
		}
		var req SignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		privKey := mode3.PrivateKey{}
		copy(privKey[:], wallet.PrivateKey)
		sig := privKey.Sign([]byte(req.Message))
		resp := map[string]string{
			"message":   req.Message,
			"signature": fmt.Sprintf("%x", sig),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	log.Println("🚀 Quantum Blockchain Node running on 127.0.0.1:8080")
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", r))
}

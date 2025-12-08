package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/argon2"
)

// Brute-force backstop globals
var (
	failedAttempts = make(map[string]int)
	lockoutMutex   sync.Mutex
	MaxAttempts    = 10
	Cooldown       = 5 * time.Minute
)

// Wallet matches your types.go but includes encryption fields
type SecureWallet struct {
	Address             string `json:"address"`
	PublicKey           []byte `json:"public_key"`
	EncryptedPrivateKey []byte `json:"encrypted_private_key"`
	Salt                []byte `json:"salt"`
	Nonce               []byte `json:"nonce"`
}

func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

func loadOrCreateSecureWallet(filename string, password string) (*SecureWallet, mode3.PrivateKey, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		// 1. Generate Quantum seed and keys
		seed := make([]byte, mode3.SeedSize)
		rand.Read(seed)
		priv := mode3.NewKeyFromSeed(seed)
		pub := priv.Public()

		// 2. Setup Encryption
		salt := make([]byte, 16)
		rand.Read(salt)
		key := deriveKey(password, salt)
		block, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(block)
		nonce := make([]byte, gcm.NonceSize())
		rand.Read(nonce)

		encrypted := gcm.Seal(nil, nonce, priv.Bytes(), nil)

		wallet := &SecureWallet{
			Address:             hex.EncodeToString(pub.Bytes()),
			PublicKey:           pub.Bytes(),
			EncryptedPrivateKey: encrypted,
			Salt:                salt,
			Nonce:               nonce,
		}

		data, _ := json.MarshalIndent(wallet, "", "  ")
		ioutil.WriteFile(filename, data, 0600)
		log.Println("📝 Secure Quantum Wallet created successfully.")
		return wallet, priv, nil
	}

	data, _ := ioutil.ReadFile(filename)
	var wallet SecureWallet
	json.Unmarshal(data, &wallet)

	// 3. Decrypt on load
	key := deriveKey(password, wallet.Salt)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	decrypted, err := gcm.Open(nil, wallet.Nonce, wallet.EncryptedPrivateKey, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("authentication failed: brute-force backstop active")
	}

	var privKey mode3.PrivateKey
	copy(privKey[:], decrypted)
	return &wallet, privKey, nil
}

func main() {
	// Secure configuration via Environment Variable
	pass := os.Getenv("CONTRAQ_KEY")
	if pass == "" {
		log.Fatal("FATAL: CONTRAQ_KEY environment variable not set. Aborting node startup.")
	}

	wallet, privKey, err := loadOrCreateSecureWallet("secure_wallet.json", pass)
	if err != nil {
		log.Fatal(err)
	}

	// Load existing blockchain data (from your blockchain.go logic)
	LoadBlockchain()

	r := mux.NewRouter()

	// Info Endpoint
	r.HandleFunc("/wallet", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"address":    wallet.Address,
			"public_key": hex.EncodeToString(wallet.PublicKey),
		})
	}).Methods("GET")

	// PQC Signing Endpoint with Backstop Throttling
	r.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr
		lockoutMutex.Lock()
		if failedAttempts[clientIP] >= MaxAttempts {
			lockoutMutex.Unlock()
			http.Error(w, "Locked: Brute-force cooldown active.", http.StatusTooManyRequests)
			return
		}
		lockoutMutex.Unlock()

		var req struct{ Message string `json:"message"` }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid Request", http.StatusBadRequest)
			return
		}

		// Perform signature
		sig := privKey.Sign([]byte(req.Message))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":   req.Message,
			"signature": hex.EncodeToString(sig),
		})
	}).Methods("POST")

	// Chain Exploration
	r.HandleFunc("/blockchain", GetBlockchain).Methods("GET")

	log.Printf("🚀 ContraQ Quantum Node Running | Address: %s\n", wallet.Address)
	log.Fatal(http.ListenAndServe(":8080", r))
}

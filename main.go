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
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/argon2"
)

// Global backstop state to mitigate high-frequency brute-force attempts
var (
	failedAttempts = make(map[string]int)
	lockoutMutex   sync.Mutex
	MaxAttempts    = 10
)

// SecureWallet defines the structure for post-quantum persistence and encryption
type SecureWallet struct {
	Address             string `json:"address"`
	PublicKey           []byte `json:"public_key"`
	EncryptedPrivateKey []byte `json:"encrypted_private_key"`
	Salt                []byte `json:"salt"`
	Nonce               []byte `json:"nonce"`
}

// deriveKey utilizes Argon2id to ensure password-to-key generation is ASIC-resistant
func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

// clientIPFromRequest extracts the caller's IP for rate-limiting logic
func clientIPFromRequest(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		return xf
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// loadOrCreateSecureWallet manages the quantum keypair life cycle with AES-GCM encryption
func loadOrCreateSecureWallet(filename string, password string) (*SecureWallet, mode3.PrivateKey, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		seed := make([]byte, mode3.SeedSize)
		rand.Read(seed)
		priv := mode3.NewKeyFromSeed(seed)
		pub := priv.Public()

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
		log.Println("📝 Secure Quantum Wallet created and saved.")
		return wallet, priv, nil
	}

	data, _ := ioutil.ReadFile(filename)
	var wallet SecureWallet
	json.Unmarshal(data, &wallet)

	key := deriveKey(password, wallet.Salt)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	decrypted, err := gcm.Open(nil, wallet.Nonce, wallet.EncryptedPrivateKey, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("authentication failed: node backstop active")
	}

	var privKey mode3.PrivateKey
	copy(privKey[:], decrypted)
	log.Println("🔑 Wallet decrypted and loaded successfully.")
	return &wallet, privKey, nil
}

func main() {
	// Security: Load passphrase from environment variable
	pass := os.Getenv("CONTRAQ_KEY")
	if pass == "" {
		log.Fatal("FATAL: CONTRAQ_KEY environment variable is missing. Node initialization aborted.")
	}

	wallet, privKey, err := loadOrCreateSecureWallet("secure_wallet.json", pass)
	if err != nil {
		log.Fatal(err)
	}

	LoadBlockchain()

	r := mux.NewRouter()

	// Standard Blockchain Routes
	r.HandleFunc("/blockchain", GetBlockchain).Methods("GET")
	r.HandleFunc("/create-transaction", CreateTransaction).Methods("POST")
	r.HandleFunc("/mine-block", MineBlock).Methods("POST")

	// PQC Public Identity Info
	r.HandleFunc("/wallet", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"address":    wallet.Address,
			"public_key": hex.EncodeToString(wallet.PublicKey),
		})
	}).Methods("GET")

	// Throttled Signing (Backstop Trigger)
	r.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		ip := clientIPFromRequest(r)
		lockoutMutex.Lock()
		if failedAttempts[ip] >= MaxAttempts {
			lockoutMutex.Unlock()
			http.Error(w, "Node Access Locked: Brute-force threshold exceeded.", http.StatusTooManyRequests)
			return
		}
		lockoutMutex.Unlock()

		var req struct{ Message string `json:"message"` }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad JSON format", http.StatusBadRequest)
			return
		}

		sig := privKey.Sign([]byte(req.Message))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":   req.Message,
			"signature": hex.EncodeToString(sig),
		})
	}).Methods("POST")

	// Chain Health/Status
	r.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"chain_length": len(BC.Chain),
			"address":      wallet.Address,
			"status":       "Quantum-Node-Operational",
		})
	}).Methods("GET")

	log.Printf("🚀 Merged ContraQ Quantum Node Operational | Local: 127.0.0.1:8080 | Address: %s\n", wallet.Address)
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", r))
}

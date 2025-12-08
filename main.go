package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
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

// Global state for brute-force backstop
var (
	failedAttempts = make(map[string]int)
	lockoutMutex   sync.Mutex
	MaxAttempts    = 10
	Cooldown       = 5 * time.Minute
)

type Wallet struct {
	PublicKey []byte `json:"public_key"`
	// EncryptedPrivateKey contains the Dilithium key encrypted with AES-GCM
	EncryptedPrivateKey []byte `json:"encrypted_private_key"`
	Salt                []byte `json:"salt"`
	Nonce               []byte `json:"nonce"`
}

// deriveKey uses Argon2id to create a 32-byte key from a password
func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

func loadOrCreateWallet(filename string, password string) (*Wallet, mode3.PrivateKey, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		// 1. Generate Quantum Keys
		var seed [32]byte
		rand.Read(seed[:])
		priv, pub := mode3.NewKeyFromSeed(&seed)

		// 2. Encrypt Private Key with Argon2 + AES
		salt := make([]byte, 16)
		rand.Read(salt)
		key := deriveKey(password, salt)
		
		block, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(block)
		nonce := make([]byte, gcm.NonceSize())
		rand.Read(nonce)

		encrypted := gcm.Seal(nil, nonce, priv.Bytes(), nil)

		wallet := &Wallet{
			PublicKey:           pub.Bytes(),
			EncryptedPrivateKey: encrypted,
			Salt:                salt,
			Nonce:               nonce,
		}
		data, _ := json.MarshalIndent(wallet, "", "  ")
		ioutil.WriteFile(filename, data, 0600)
		log.Println("📝 Secure Encrypted Wallet Created")
		return wallet, priv, nil
	}

	// 3. Load and Decrypt
	data, _ := ioutil.ReadFile(filename)
	var wallet Wallet
	json.Unmarshal(data, &wallet)

	key := deriveKey(password, wallet.Salt)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	
	decrypted, err := gcm.Open(nil, wallet.Nonce, wallet.EncryptedPrivateKey, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("incorrect passphrase - brute force backstop potential")
	}

	var privKey mode3.PrivateKey
	copy(privKey[:], decrypted)
	log.Println("🔑 Wallet Decrypted & Loaded")
	return &wallet, privKey, nil
}

func main() {
	// In production, get this from an environment variable or secure CLI input
	nodePassphrase := "BabyStepsToTheBillion$$" 
	
	wallet, privKey, err := loadOrCreateWallet("wallet.json", nodePassphrase)
	if err != nil {
		log.Fatal(err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/wallet", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"public_key": fmt.Sprintf("%x", wallet.PublicKey),
		})
	})

	r.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr
		lockoutMutex.Lock()
		if failedAttempts[clientIP] >= MaxAttempts {
			lockoutMutex.Unlock()
			http.Error(w, "Locked: Brute-force backstop active. Cooldown triggered.", http.StatusTooManyRequests)
			return
		}
		lockoutMutex.Unlock()

		var req struct{ Message string `json:"message"` }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid Request", http.StatusBadRequest)
			return
		}

		// Simulate signing logic
		sig := privKey.Sign([]byte(req.Message))
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": req.Message,
			"signature": fmt.Sprintf("%x", sig),
		})
	}).Methods("POST")

	log.Println("🚀 Quantum-Safe ContraQ Node running on 127.0.0.1:8080")
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", r))
}

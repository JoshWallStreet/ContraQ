package main

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
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

// Brute-force backstop globals
var (
	failedAttempts = make(map[string]int)
	lockoutMutex   sync.Mutex
	MaxAttempts    = 10
	lockedUntil    = make(map[string]time.Time)
)

// SecureWallet structure for persistence with Argon2id protection
type SecureWallet struct {
	Address             string `json:"address"`
	PublicKey           []byte `json:"public_key"`
	EncryptedPrivateKey []byte `json:"encrypted_private_key"`
	Salt                []byte `json:"salt"`
	Nonce               []byte `json:"nonce"`
}

// deriveKey utilizes Argon2id (Time: 1, Memory: 64MB, Parallelism: 4) to protect secrets
func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

func clientIPFromRequest(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		return xf
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		return r.RemoteAddr
	}
	return host
}

func recordFailedAttempt(ip string) {
	lockoutMutex.Lock()
	defer lockoutMutex.Unlock()
	failedAttempts[ip]++
	if failedAttempts[ip] >= MaxAttempts {
		lockedUntil[ip] = time.Now().Add(5 * time.Minute)
		log.Printf("🚨 BACKSTOP TRIGGERED: IP %s restricted after %d attempts.", ip, MaxAttempts)
	}
}

func isLocked(ip string) bool {
	lockoutMutex.Lock()
	defer lockoutMutex.Unlock()
	if until, ok := lockedUntil[ip]; ok {
		return time.Now().Before(until)
	}
	return false
}

// LoadOrCreateKeystore creates a lattice-based identity or loads an existing encrypted one
func LoadOrCreateKeystore(filename, password string) (*SecureWallet, mode3.PrivateKey, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		var seed [32]byte
		crand.Read(seed[:])
		priv, pub := mode3.NewKeyFromSeed(&seed)

		salt, nonce := make([]byte, 16), make([]byte, 12) // GCM Nonce size 12
		crand.Read(salt)
		crand.Read(nonce)

		key := deriveKey(password, salt)
		block, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(block)
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
		log.Println("📝 Quantum Keystore created with Argon2id protection.")
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
		return nil, nil, fmt.Errorf("node security violation: decryption failed")
	}

	var privKey mode3.PrivateKey
	copy(privKey[:], decrypted)
	log.Println("🔑 Keystore successfully decrypted and loaded.")
	return &wallet, privKey, nil
}

func main() {
	// BabyStepsToTheBillion$$ - Ensure environment variable is set
	pass := os.Getenv("CONTRAQ_KEY")
	if pass == "" {
		log.Fatal("ERROR: Node requires CONTRAQ_KEY environment variable to secure PQC identities.")
	}

	r := mux.NewRouter()
	ks, priv, err := LoadOrCreateKeystore("secure_wallet.json", pass)
	if err != nil {
		log.Fatal(err)
	}

	// GET: Retrieve Node Public Identity
	r.HandleFunc("/wallet", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"address": ks.Address, 
			"pqc_pub": hex.EncodeToString(ks.PublicKey),
		})
	}).Methods("GET")

	// POST: Throttled Post-Quantum Message Signing
	r.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		ip := clientIPFromRequest(r)
		if isLocked(ip) {
			http.Error(w, "Locked: Brute-force threshold exceeded.", http.StatusTooManyRequests)
			return
		}

		var req struct{ Message string `json:"message"` }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			recordFailedAttempt(ip)
			http.Error(w, "Invalid Request Body", http.StatusBadRequest)
			return
		}

		sig := priv.Sign([]byte(req.Message))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"msg": req.Message, 
			"sig": hex.EncodeToString(sig),
		})
	}).Methods("POST")

	log.Printf("🚀 ContraQ Node Live | ID: %s", ks.Address)
	log.Fatal(http.ListenAndServe(":8080", r))
}

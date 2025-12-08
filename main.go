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

// Global backstop state
var (
	failedAttempts = make(map[string]int)
	lockoutMutex   sync.Mutex
	MaxAttempts    = 10
	lockedUntil    = make(map[string]time.Time)
)

// SecureWallet structure (on-disk)
type SecureWallet struct {
	Address             string `json:"address"`
	PublicKey           []byte `json:"public_key"`
	EncryptedPrivateKey []byte `json:"encrypted_private_key"`
	Salt                []byte `json:"salt"`
	Nonce               []byte `json:"nonce"`
}

// deriveKey (Argon2id) makes brute-forcing password attempts hardware-expensive
func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

// clientIPFromRequest detects the actual caller IP for rate limiting
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

// recordFailedAttempt increments and applies simple cooldown to stop brute force
func recordFailedAttempt(ip string) {
	lockoutMutex.Lock()
	defer lockoutMutex.Unlock()
	failedAttempts[ip]++
	if failedAttempts[ip] >= MaxAttempts {
		lockedUntil[ip] = time.Now().Add(5 * time.Minute)
		log.Printf("IP %s locked until %s (count=%d)\n", ip, lockedUntil[ip].Format(time.RFC3339), failedAttempts[ip])
	}
}

// isLocked checks if an IP is currently within a backstop lockout period
func isLocked(ip string) bool {
	lockoutMutex.Lock()
	defer lockoutMutex.Unlock()
	if until, ok := lockedUntil[ip]; ok {
		return time.Now().Before(until)
	}
	return false
}

// LoadOrCreateKeystore creates a lattice-based identity or loads an encrypted one
func LoadOrCreateKeystore(filename, password string) (*SecureWallet, mode3.PrivateKey, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		var seed [32]byte
		if _, err := crand.Read(seed[:]); err != nil {
			return nil, nil, fmt.Errorf("seed read failed: %v", err)
		}
		priv, pub := mode3.NewKeyFromSeed(&seed)

		salt := make([]byte, 16)
		crand.Read(salt)
		key := deriveKey(password, salt)
		block, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(block)
		nonce := make([]byte, gcm.NonceSize())
		crand.Read(nonce)
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
		log.Println("📝 Secure Quantum Wallet created.")
		return wallet, priv, nil
	}

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, nil, err
	}
	var wallet SecureWallet
	json.Unmarshal(data, &wallet)
	key := deriveKey(password, wallet.Salt)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	decrypted, err := gcm.Open(nil, wallet.Nonce, wallet.EncryptedPrivateKey, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("authentication failed: %v", err)
	}
	var privKey mode3.PrivateKey
	copy(privKey[:], decrypted)
	return &wallet, privKey, nil
}

func main() {
	// SECURE PASSPHRASE CHECK
	pass := os.Getenv("CONTRAQ_KEY")
	if pass == "" {
		log.Fatal("ERROR: CONTRAQ_KEY not set.")
	}

	r := mux.NewRouter()
	
	// Initialize Keystore and Routes
	ks, priv, err := LoadOrCreateKeystore("secure_wallet.json", pass)
	if err != nil {
		log.Fatal(err)
	}

	// GET: Node Identity info
	r.HandleFunc("/wallet", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"address":    ks.Address,
			"public_key": hex.EncodeToString(ks.PublicKey),
		})
	}).Methods("GET")

	// POST: Throttled Post-Quantum Signing
	r.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		ip := clientIPFromRequest(r)
		if isLocked(ip) {
			http.Error(w, "Locked: Brute-force cooldown in effect.", http.StatusTooManyRequests)
			return
		}

		var req struct{ Message string `json:"message"` }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			recordFailedAttempt(ip)
			http.Error(w, "Bad JSON Request", http.StatusBadRequest)
			return
		}

		sig := priv.Sign([]byte(req.Message))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":   req.Message,
			"signature": hex.EncodeToString(sig),
		})
	}).Methods("POST")

	// Initialize external blockchain logic if needed
	// LoadBlockchain()

	log.Println("🚀 ContraQ Merged Node running on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

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

var (
	failedAttempts = make(map[string]int)
	lockoutMutex   sync.Mutex
	MaxAttempts    = 10
	lockedUntil    = make(map[string]time.Time)
)

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
		log.Printf("🚨 Node Alert: IP %s locked (threshold hit)", ip)
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

func LoadOrCreateKeystore(filename, password string) (*SecureWallet, mode3.PrivateKey, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		var seed [32]byte
		crand.Read(seed[:])
		priv, pub := mode3.NewKeyFromSeed(&seed)

		salt, nonce := make([]byte, 16), make([]byte, 12)
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
		return nil, nil, fmt.Errorf("decryption failed: node is secure")
	}

	var privKey mode3.PrivateKey
	copy(privKey[:], decrypted)
	return &wallet, privKey, nil
}

func main() {
	pass := os.Getenv("CONTRAQ_KEY")
	if pass == "" {
		log.Fatal("ERROR: Secure node requires CONTRAQ_KEY environment variable.")
	}

	r := mux.NewRouter()
	ks, priv, err := LoadOrCreateKeystore("secure_wallet.json", pass)
	if err != nil {
		log.Fatal(err)
	}

	r.HandleFunc("/wallet", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"address": ks.Address, "pqc_pub": hex.EncodeToString(ks.PublicKey)})
	}).Methods("GET")

	r.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		ip := clientIPFromRequest(r)
		if isLocked(ip) {
			http.Error(w, "Locked: Too many attempts.", http.StatusTooManyRequests)
			return
		}
		var req struct{ Message string `json:"message"` }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			recordFailedAttempt(ip)
			http.Error(w, "Bad JSON", http.StatusBadRequest)
			return
		}
		sig := priv.Sign([]byte(req.Message))
		json.NewEncoder(w).Encode(map[string]string{"msg": req.Message, "sig": hex.EncodeToString(sig)})
	}).Methods("POST")

	log.Printf("🚀 ContraQ Quantum Node Operational | Address: %s", ks.Address)
	log.Fatal(http.ListenAndServe(":8080", r))
}

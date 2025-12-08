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

// Global State
var (
	lockoutMutex   sync.Mutex
	failedAttempts = make(map[string]int)
	MaxAttempts    = 10
	Cooldown       = 5 * time.Minute
)

// Node State
type ContraQNode struct {
	Wallet     *Wallet
	PrivKey    mode3.PrivateKey
	Blockchain []string // Mock persistent ledger
	mu         sync.Mutex
}

type Wallet struct {
	PublicKey           []byte `json:"public_key"`
	EncryptedPrivateKey []byte `json:"encrypted_private_key"`
	Salt                []byte `json:"salt"`
	Nonce               []byte `json:"nonce"`
}

// Security: Derive key from environment passphrase
func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

func loadOrCreateWallet(filename string, password string) (*Wallet, mode3.PrivateKey, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		var seed [32]byte
		rand.Read(seed[:])
		priv, pub := mode3.NewKeyFromSeed(&seed)

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
		return wallet, priv, nil
	}

	data, _ := ioutil.ReadFile(filename)
	var wallet Wallet
	json.Unmarshal(data, &wallet)

	key := deriveKey(password, wallet.Salt)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	
	decrypted, err := gcm.Open(nil, wallet.Nonce, wallet.EncryptedPrivateKey, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("incorrect passphrase - check environment variable")
	}

	var privKey mode3.PrivateKey
	copy(privKey[:], decrypted)
	return &wallet, privKey, nil
}

func main() {
	// SECURE PASSPHRASE CHECK
	nodePassphrase := os.Getenv("CONTRAQ_PASSPHRASE")
	if nodePassphrase == "" {
		log.Fatal("ERROR: Set CONTRAQ_PASSPHRASE environment variable.")
	}

	wallet, privKey, err := loadOrCreateWallet("wallet.json", nodePassphrase)
	if err != nil {
		log.Fatal(err)
	}

	node := &ContraQNode{Wallet: wallet, PrivKey: privKey, Blockchain: []string{"GENESIS_BLOCK"}}
	r := mux.NewRouter()

	// Endpoints
	r.HandleFunc("/wallet", node.getWalletHandler).Methods("GET")
	r.HandleFunc("/sign", node.signHandler).Methods("POST")
	r.HandleFunc("/verify", node.verifyHandler).Methods("POST")
	r.HandleFunc("/blocks", node.getBlocksHandler).Methods("GET")

	log.Println("🚀 ContraQ Quantum Node running on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

// Handlers
func (n *ContraQNode) getWalletHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"public_key": hex.EncodeToString(n.Wallet.PublicKey)})
}

func (n *ContraQNode) signHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	lockoutMutex.Lock()
	if failedAttempts[clientIP] >= MaxAttempts {
		lockoutMutex.Unlock()
		http.Error(w, "Brute-force backstop: Cooldown active.", http.StatusTooManyRequests)
		return
	}
	lockoutMutex.Unlock()

	var req struct{ Message string `json:"message"` }
	json.NewDecoder(r.Body).Decode(&req)
	sig := n.PrivKey.Sign([]byte(req.Message))

	json.NewEncoder(w).Encode(map[string]string{
		"message": req.Message,
		"signature": hex.EncodeToString(sig),
	})
}

func (n *ContraQNode) verifyHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message   string `json:"message"`
		Signature string `json:"signature"`
		PublicKey string `json:"public_key"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	
	sig, _ := hex.DecodeString(req.Signature)
	pkBytes, _ := hex.DecodeString(req.PublicKey)
	
	var pk mode3.PublicKey
	pk.UnmarshalBinary(pkBytes)
	
	isValid := mode3.Verify(&pk, []byte(req.Message), sig)
	json.NewEncoder(w).Encode(map[string]bool{"is_valid": isValid})
}

func (n *ContraQNode) getBlocksHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(n.Blockchain)
}

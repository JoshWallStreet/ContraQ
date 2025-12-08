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
	"net/http"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

// Keystore - encrypted on-disk wallet container (separate from on-chain Wallet type)
type Keystore struct {
	PublicKey           []byte    `json:"public_key"`
	EncryptedPrivateKey []byte    `json:"encrypted_private_key"`
	Salt                []byte    `json:"salt"`
	Nonce               []byte    `json:"nonce"`
	CreatedAt           time.Time `json:"created_at"`
}

const (
	DefaultKeystoreFile = "keystore.json"
)

// Harder Argon2id params for production-like protection (tune for your environment)
const (
	argon2Time       = 3            // iterations
	argon2MemoryKB   = 256 * 1024   // 256 MB
	argon2Parallel   = 4
	argon2KeyLen     = 32
	keystoreFileMode = 0600
)

// deriveKeyArgon2 returns a 32-byte key using Argon2id. These parameters are stronger than dev defaults.
func deriveKeyArgon2(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2MemoryKB, argon2Parallel, argon2KeyLen)
}

// addressFromPub returns a compact, easy-to-read address derived from the public key
// Uses SHA3-256(pubkey) and returns hex of first 20 bytes (short address)
func addressFromPub(pub []byte) string {
	h := sha3.New256()
	h.Write(pub)
	s := h.Sum(nil)
	return hex.EncodeToString(s[:20])
}

// GenerateKeystore generates a Dilithium keypair, encrypts the private key with passphrase and writes keystore to disk
func GenerateKeystore(filename, passphrase string) (*Keystore, mode3.PrivateKey, error) {
	// 1) seed
	var seed [32]byte
	if _, err := crand.Read(seed[:]); err != nil {
		return nil, nil, fmt.Errorf("seed gen failed: %v", err)
	}
	priv, pub := mode3.NewKeyFromSeed(&seed)

	// 2) derive symmetric key
	salt := make([]byte, 16)
	if _, err := crand.Read(salt); err != nil {
		return nil, nil, err
	}
	key := deriveKeyArgon2(passphrase, salt)

	// 3) AES-GCM encrypt private key bytes
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := crand.Read(nonce); err != nil {
		return nil, nil, err
	}
	encrypted := gcm.Seal(nil, nonce, priv.Bytes(), nil)

	ks := &Keystore{
		PublicKey:           pub.Bytes(),
		EncryptedPrivateKey: encrypted,
		Salt:                salt,
		Nonce:               nonce,
		CreatedAt:           time.Now().UTC(),
	}

	// write to file
	data, _ := json.MarshalIndent(ks, "", "  ")
	if err := ioutil.WriteFile(filename, data, keystoreFileMode); err != nil {
		return nil, nil, err
	}
	log.Println("📝 New encrypted keystore created:", filename)
	return ks, priv, nil
}

// LoadKeystore loads and decrypts keystore file using passphrase
func LoadKeystore(filename, passphrase string) (*Keystore, mode3.PrivateKey, error) {
	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, nil, err
	}
	var ks Keystore
	if err := json.Unmarshal(raw, &ks); err != nil {
		return nil, nil, err
	}
	key := deriveKeyArgon2(passphrase, ks.Salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	privBytes, err := gcm.Open(nil, ks.Nonce, ks.EncryptedPrivateKey, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt keystore: %v", err)
	}
	var priv mode3.PrivateKey
	copy(priv[:], privBytes)
	return &ks, priv, nil
}

// VerifySignature verifies a signature against a public key (hex). Returns boolean.
func VerifySignature(pubHex, msg, sigHex string) (bool, error) {
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		return false, err
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return false, err
	}
	var pub mode3.PublicKey
	copy(pub[:], pubBytes)
	ok := mode3.Verify(&pub, []byte(msg), sigBytes)
	return ok, nil
}

// HTTP Handlers ---------------------------------------------------------------

// CreateWalletAPI creates a new keystore on disk. Expects JSON: {"passphrase":"...","file":"..."}.
// Response: {"address":"...","public_key":"..."}
func CreateWalletAPI(w http.ResponseWriter, r *http.Request) {
	type reqT struct {
		Passphrase string `json:"passphrase"`
		File       string `json:"file"`
	}
	var req reqT
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Passphrase == "" {
		http.Error(w, "passphrase required", http.StatusBadRequest)
		return
	}
	file := req.File
	if file == "" {
		file = DefaultKeystoreFile
	}
	ks, _, err := GenerateKeystore(file, req.Passphrase)
	if err != nil {
		http.Error(w, fmt.Sprintf("create keystore failed: %v", err), http.StatusInternalServerError)
		return
	}
	addr := addressFromPub(ks.PublicKey)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"address": addr, "public_key": hex.EncodeToString(ks.PublicKey)})
}

// SignAPI signs a message using an existing keystore. Expects JSON: {"passphrase":"...","file":"keystore.json","message":"..."}.
func SignAPI(w http.ResponseWriter, r *http.Request) {
	type reqT struct {
		Passphrase string `json:"passphrase"`
		File       string `json:"file"`
		Message    string `json:"message"`
	}
	var req reqT
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Passphrase == "" || req.Message == "" {
		http.Error(w, "passphrase and message required", http.StatusBadRequest)
		return
	}
	file := req.File
	if file == "" {
		file = DefaultKeystoreFile
	}
	ks, priv, err := LoadKeystore(file, req.Passphrase)
	if err != nil {
		http.Error(w, fmt.Sprintf("load keystore failed: %v", err), http.StatusUnauthorized)
		return
	}
	sig := priv.Sign([]byte(req.Message))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": req.Message, "signature": hex.EncodeToString(sig), "pubkey": hex.EncodeToString(ks.PublicKey)})
}

// VerifyAPI is an HTTP wrapper for VerifySignature. Expects JSON {"pubkey":"...","message":"...","signature":"..."}
func VerifyAPI(w http.ResponseWriter, r *http.Request) {
	type reqT struct {
		PubKey   string `json:"pubkey"`
		Message  string `json:"message"`
		Signature string `json:"signature"`
	}
	var req reqT
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	ok, err := VerifySignature(req.PubKey, req.Message, req.Signature)
	if err != nil {
		http.Error(w, fmt.Sprintf("verify error: %v", err), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(map[string]bool{"valid": ok})
}

// WireHandlers helper
func WireWalletHandlers(r *mux.Router) {
	r.HandleFunc("/wallet/create", CreateWalletAPI).Methods("POST")
	r.HandleFunc("/wallet/sign", SignAPI).Methods("POST")
	r.HandleFunc("/wallet/verify", VerifyAPI).Methods("POST")
}

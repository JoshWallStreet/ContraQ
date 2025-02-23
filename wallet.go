package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// Load wallets from file
func LoadWallets() {
	data, err := os.ReadFile(walletsFile)
	if err == nil {
		json.Unmarshal(data, &BC.Wallets)
	}
}

// Save wallets to file
func SaveWallets() {
	data, _ := json.Marshal(BC.Wallets)
	os.WriteFile(walletsFile, data, 0644)
}

// Create a new wallet
func CreateWallet() *Wallet {
	privateKey, publicKey, _ := mode3.GenerateKey(rand.Reader)
	address := hex.EncodeToString(publicKey.Bytes())[:12]

	wallet := &Wallet{
		Address:    address,
		Balance:    1000,
		Stake:      0,
		Nonce:      0,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}

	BC.mutex.Lock()
	defer BC.mutex.Unlock()
	BC.Wallets = append(BC.Wallets, wallet)
	SaveWallets()
	log.Println("✅ Wallet Created: ", address)
	return wallet
}

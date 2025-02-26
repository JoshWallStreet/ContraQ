package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// Wallet structure with Dilithium PQC keys
type Wallet struct {
	Address    string            `json:"address"`
	PrivateKey *mode3.PrivateKey `json:"-"`
	PublicKey  *mode3.PublicKey  `json:"-"`
}

// GenerateWallet creates a new wallet with a Dilithium key pair
func GenerateWallet() *Wallet {
	// Generate a secure random seed
	seed := make([]byte, mode3.SeedSize)
	_, err := rand.Read(seed)
	if err != nil {
		log.Fatal("❌ Failed to generate random seed:", err)
	}

	// Generate Dilithium keys from the seed
	priv := mode3.NewKeyFromSeed(seed)
	pub := priv.Public()

	// Create a wallet
	return &Wallet{
		Address:    hex.EncodeToString(pub.Bytes()), // Address derived from public key
		PrivateKey: priv,
		PublicKey:  pub,
	}
}

func main() {
	// Generate and display the wallet
	wallet := GenerateWallet()
	fmt.Println("✅ Wallet Created!")
	fmt.Printf("📜 Address: %s\n", wallet.Address)
}

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// Wallet contains Dilithium public + private key pair
type Wallet struct {
	Address      string `json:"address"`
	PublicKeyHex string `json:"public_key"`
	// PrivateKey is intentionally omitted from JSON export for safety
	PrivateKey *mode3.PrivateKey
	PublicKey  *mode3.PublicKey
}

// GenerateWallet creates a Dilithium Mode3 quantum-safe wallet
func GenerateWallet() *Wallet {
	// Create 32-byte seed (correct size for Dilithium Mode 3)
	var seed [32]byte
	_, err := rand.Read(seed[:])
	if err != nil {
		log.Fatal("Failed to generate random seed:", err)
	}

	// CIRCL API: NewKeyFromSeed returns (PrivateKey, PublicKey)
	priv, pub := mode3.NewKeyFromSeed(&seed)

	// The address is simply the hex of the public key for now
	address := hex.EncodeToString(pub.Bytes())

	return &Wallet{
		Address:      address,
		PublicKeyHex: hex.EncodeToString(pub.Bytes()),
		PrivateKey:   priv,
		PublicKey:    pub,
	}
}

func main() {
	w := GenerateWallet()

	fmt.Println("========================================")
	fmt.Println("      ContraQ Quantum-Safe Wallet")
	fmt.Println("========================================")
	fmt.Printf("Address (Public Key): %s\n", w.Address)
	fmt.Println("========================================")
}

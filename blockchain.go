package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// Load blockchain from file or create genesis block
func LoadBlockchain() {
	data, err := os.ReadFile(blockchainFile)
	if err != nil {
		log.Println("No blockchain found, creating genesis block...")
		createGenesisBlock()
		return
	}
	if err := json.Unmarshal(data, &BC.Chain); err != nil {
		log.Println("Blockchain data corrupted, resetting...")
		createGenesisBlock()
	}
}

// Create the first block (Genesis Block)
func createGenesisBlock() {
	genesis := Block{
		Index:        0,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Transactions: []Transaction{},
		PreviousHash: "0",
		Validator:    "genesis-node",
	}
	genesis.Hash = calculateHash(genesis)
	BC.Chain = []Block{genesis}
	saveBlockchain()
	log.Println("✅ Genesis Block Created!")
}

// Calculate block hash
func calculateHash(b Block) string {
	data := fmt.Sprintf("%d%s%v%s%s", b.Index, b.Timestamp, b.Transactions, b.PreviousHash, b.Validator)
	hash := mode3.Hash([]byte(data))
	return hex.EncodeToString(hash)
}

// Save blockchain to file
func saveBlockchain() {
	data, _ := json.Marshal(BC.Chain)
	os.WriteFile(blockchainFile, data, 0644)
}

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
	"net/http"
	"github.com/gorilla/mux"
)

// Blockchain structure
type Blockchain struct {
	Chain     []Block
	PendingTx []Transaction
	mutex     sync.Mutex
}

// Block structure
type Block struct {
	Index        int
	Timestamp    string
	Transactions []Transaction
	PreviousHash string
	Hash         string
	Validator    string
}

// Transaction structure
type Transaction struct {
	Sender    string
	Receiver  string
	Amount    int
	Signature string
}

// Global blockchain instance
var bc Blockchain
var blockchainFile = "blockchain.json"

// Load blockchain from file
func LoadBlockchain() {
	data, err := os.ReadFile(blockchainFile)
	if err != nil {
		log.Println("No existing blockchain found. Creating genesis block...")
		createGenesisBlock()
		return
	}

	json.Unmarshal(data, &bc.Chain)
}

// Create the first block (Genesis Block)
func createGenesisBlock() {
	genesis := Block{
		Index:        0,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Transactions: []Transaction{},
		PreviousHash: "0",
		Validator:    "genesis",
	}
	genesis.Hash = calculateHash(genesis)
	bc.Chain = append(bc.Chain, genesis)
	saveBlockchain()
}

// Calculate block hash using SHA-256
func calculateHash(b Block) string {
	data := fmt.Sprintf("%d%s%v%s%s", b.Index, b.Timestamp, b.Transactions, b.PreviousHash, b.Validator)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:])
}

// Save blockchain to file
func saveBlockchain() {
	data, _ := json.Marshal(bc.Chain)
	os.WriteFile(blockchainFile, data, 0644)
}

// API: Get blockchain
func GetBlockchain(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(bc.Chain)
}

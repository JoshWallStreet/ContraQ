package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/gorilla/mux"
)

// --- STRUCT DEFINITIONS ---

// Block structure
type Block struct {
	Index        int
	Timestamp    string
	Transactions []Transaction
	PreviousHash string
	Hash         string
	Validator    string
}

// Transaction using quantum-safe cryptography
type Transaction struct {
	Sender          string
	SenderPublicKey []byte
	Receiver        string
	Amount          int
	Timestamp       string
	Signature       string
}

// Wallet structure (Quantum-Safe)
type Wallet struct {
	Address    string
	Balance    int
	Stake      int
	PrivateKey *mode3.PrivateKey
	PublicKey  *mode3.PublicKey
}

// Order structure for exchange (Buy/Sell)
type Order struct {
	ID       int
	Wallet   *Wallet
	Type     string
	Amount   int
	Price    float64
	Filled   bool
}

// --- GLOBAL STATE VARIABLES ---
var Blockchain []Block
var Transactions []Transaction
var Orders []Order
var Wallets []*Wallet
var TotalSupply int = 1000000
var blockchainFile = "blockchain.json"

// --- FUNCTION DEFINITIONS ---

// Calculate Hash for block integrity
func calculateHash(b Block) string {
	record := fmt.Sprintf("%d%s%s%s%s", b.Index, b.Timestamp, b.Transactions, b.PreviousHash, b.Validator)
	hash := mode3.Hash(record)
	return hex.EncodeToString(hash[:])
}

// Generate a quantum-resistant wallet
func generateWallet() *Wallet {
	privateKey, publicKey, err := mode3.GenerateKey(nil)
	if err != nil {
		log.Fatalf("Key generation failed: %v", err)
	}
	address := hex.EncodeToString(publicKey.Bytes())[:12]
	wallet := &Wallet{Address: address, Balance: 100, Stake: 0, PrivateKey: privateKey, PublicKey: publicKey}
	Wallets = append(Wallets, wallet)
	return wallet
}

// Sign transaction using Dilithium
func signTransaction(wallet *Wallet, tx *Transaction) {
	msg := []byte(fmt.Sprintf("%s%s%d%s", tx.Sender, tx.Receiver, tx.Amount, tx.Timestamp))
	signature, err := wallet.PrivateKey.Sign(rand.Reader, msg, nil)
	if err != nil {
		log.Fatalf("Signing failed: %v", err)
	}
	tx.Signature = hex.EncodeToString(signature)
}

// Verify a transaction
func verifyTransaction(tx Transaction) bool {
	msg := []byte(fmt.Sprintf("%s%s%d%s", tx.Sender, tx.Receiver, tx.Amount, tx.Timestamp))
	signature, err := hex.DecodeString(tx.Signature)
	if err != nil {
		return false
	}
	publicKey := mode3.PublicKey{}
	if err := publicKey.UnmarshalBinary(tx.SenderPublicKey); err != nil {
		return false
	}
	return publicKey.Verify(msg, signature)
}

// Select validator based on stake (PoS)
func selectValidator() *Wallet {
	totalStake := 0
	for _, w := range Wallets {
		totalStake += w.Stake
	}
	if totalStake == 0 {
		return Wallets[0] // Default to first wallet
	}
	randStake, _ := rand.Int(rand.Reader, big.NewInt(int64(totalStake)))
	for _, w := range Wallets {
		randStake.Sub(randStake, big.NewInt(int64(w.Stake)))
		if randStake.Sign() <= 0 {
			return w
		}
	}
	return nil
}

// Mine block (Proof of Stake)
func mineBlock() {
	if len(Transactions) == 0 {
		fmt.Println("No transactions to mine.")
		return
	}

	validator := selectValidator()
	newBlock := Block{
		Index:        len(Blockchain),
		Timestamp:    time.Now().String(),
		Transactions: Transactions,
		PreviousHash: Blockchain[len(Blockchain)-1].Hash,
		Validator:    validator.Address,
	}
	newBlock.Hash = calculateHash(newBlock)
	Blockchain = append(Blockchain, newBlock)
	validator.Balance += 10
	Transactions = nil
	fmt.Printf("Mined block! Validator %s rewarded 10 QOIN.\n", validator.Address)
}

// Send coins between wallets
func sendCoins(sender, receiver *Wallet, amount int) {
	if sender.Balance < amount {
		fmt.Println("Insufficient balance!")
		return
	}

	tx := Transaction{
		Sender:          sender.Address,
		SenderPublicKey: sender.PublicKey.Bytes(),
		Receiver:        receiver.Address,
		Amount:          amount,
		Timestamp:       time.Now().String(),
	}
	signTransaction(sender, &tx)

	if verifyTransaction(tx) {
		Transactions = append(Transactions, tx)
		sender.Balance -= amount
		receiver.Balance += amount
		fmt.Printf("Transaction successful! %d QOIN sent from %s to %s.\n", amount, sender.Address, receiver.Address)
	} else {
		fmt.Println("Transaction verification failed!")
	}
}

// --- API HANDLERS ---

// API: Get blockchain
func getBlockchain(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(Blockchain)
}

// API: Create a wallet
func createWallet(w http.ResponseWriter, r *http.Request) {
	wallet := generateWallet()
	json.NewEncoder(w).Encode(wallet)
}

// API: Send transaction
func sendTransaction(w http.ResponseWriter, r *http.Request) {
	var tx Transaction
	_ = json.NewDecoder(r.Body).Decode(&tx)
	if verifyTransaction(tx) {
		Transactions = append(Transactions, tx)
		json.NewEncoder(w).Encode("Transaction added!")
	} else {
		json.NewEncoder(w).Encode("Transaction failed!")
	}
}

// API: Mine block (PoS)
func mineBlockHandler(w http.ResponseWriter, r *http.Request) {
	mineBlock()
	json.NewEncoder(w).Encode("Block mined successfully!")
}

// --- SERVER SETUP ---

func startServer() {
	router := mux.NewRouter()
	router.HandleFunc("/blockchain", getBlockchain).Methods("GET")
	router.HandleFunc("/wallet", createWallet).Methods("POST")
	router.HandleFunc("/transaction", sendTransaction).Methods("POST")
	router.HandleFunc("/mine", mineBlockHandler).Methods("POST")

	fmt.Println("🚀 Q-O-I-N Blockchain Running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}

// --- MAIN FUNCTION ---
func main() {
	// Initialize blockchain
	genesisBlock := Block{Index: 0, Timestamp: time.Now().String(), Transactions: nil, PreviousHash: "0", Validator: "Genesis"}
	genesisBlock.Hash = calculateHash(genesisBlock)
	Blockchain = append(Blockchain, genesisBlock)

	// Start server
	go startServer()

	fmt.Println("🚀 Quantum Blockchain & Exchange Running!")
	select {} // Keep running
}

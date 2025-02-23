package main

import (
	"encoding/json"
	"net/http"
)

// Get blockchain data
func GetBlockchain(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(BC.Chain)
}

// API to create a wallet
func CreateWalletHandler(w http.ResponseWriter, r *http.Request) {
	wallet := CreateWallet()
	json.NewEncoder(w).Encode(struct {
		Address string `json:"address"`
		Balance int    `json:"balance"`
	}{
		wallet.Address,
		wallet.Balance,
	})
}

// Placeholder for transaction creation
func CreateTransaction(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode("CreateTransaction: Under Development")
}

// Placeholder for mining a block
func MineBlock(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode("MineBlock: Under Development")
}

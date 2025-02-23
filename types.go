package main

import (
	"sync"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

type Blockchain struct {
	Chain     []Block
	PendingTx []Transaction
	Wallets   []*Wallet
	mutex     sync.Mutex
}

type Block struct {
	Index        int           `json:"index"`
	Timestamp    string        `json:"timestamp"`
	Transactions []Transaction `json:"transactions"`
	PreviousHash string        `json:"previousHash"`
	Hash         string        `json:"hash"`
	Validator    string        `json:"validator"`
}

type Transaction struct {
	Sender    string `json:"sender"`
	Receiver  string `json:"receiver"`
	Amount    int    `json:"amount"`
	Nonce     int    `json:"nonce"`
	Signature string `json:"signature"`
}

type Wallet struct {
	Address    string            `json:"address"`
	Balance    int               `json:"balance"`
	Stake      int               `json:"stake"`
	Nonce      int               `json:"nonce"`
	PrivateKey *mode3.PrivateKey `json:"-"`
	PublicKey  *mode3.PublicKey  `json:"-"`
}

const (
	blockchainFile = "blockchain.json"
	walletsFile    = "wallets.json"
	reward         = 10
)

var BC = Blockchain{}

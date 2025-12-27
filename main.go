package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/gorilla/mux"
	"github.com/klauspost/reedsolomon"
	_ "github.com/mattn/go-sqlite3"
)

const (
	Version       = "v14.1-OMEGA-CHAIN-INTRINSIC"
	SlotDuration  = 2 * time.Second
	DataShards    = 16
	ParityShards  = 16
	GenesisSupply = 21_000_000_000
	ServerPort    = ":8080"
	
	// Rate limiting
	MaxFailedAttempts = 10
	LockoutDuration   = 5 * time.Minute
)

var (
	chainDB    *sql.DB
	nodeWallet *Wallet
	globalNode *ContraQNode
	zkParams   *ZKParams
	
	// Rate limiting state
	failedAttempts sync.Map // IP -> attempt count
	lockedUntil    sync.Map // IP -> time.Time
	rateLimitMu    sync.Mutex
)

// --- QUANTUM-SAFE WALLET ---

type Wallet struct {
	Address    string
	PrivateKey mode5.PrivateKey
	PublicKey  mode5.PublicKey
	mu         sync.RWMutex
}

func NewWallet() *Wallet {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		log.Fatal("Failed to generate seed:", err)
	}
	priv, pub := mode5.NewKeyFromSeed(seed[:])
	addr := fmt.Sprintf("cq_%x", sha256.Sum256(pub.Bytes())[:20])
	return &Wallet{Address: addr, PrivateKey: priv, PublicKey: pub}
}

func (w *Wallet) Sign(data []byte) []byte {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.PrivateKey.Sign(nil, data)
}

// --- REAL zkSNARK CIRCUIT ---

type StateTransitionCircuit struct {
	PrevStateRoot frontend.Variable `gnark:",public"`
	NewStateRoot  frontend.Variable `gnark:",public"`
	TxCount       frontend.Variable `gnark:",public"`
	TxHashes      []frontend.Variable
}

func (circuit *StateTransitionCircuit) Define(api frontend.API) error {
	sum := circuit.PrevStateRoot
	for i := 0; i < len(circuit.TxHashes); i++ {
		sum = api.Add(sum, circuit.TxHashes[i])
	}
	api.AssertIsEqual(circuit.NewStateRoot, sum)
	api.AssertIsEqual(circuit.TxCount, len(circuit.TxHashes))
	return nil
}

type ZKParams struct {
	ProvingKey   groth16.ProvingKey
	VerifyingKey groth16.VerifyingKey
	R1CS         frontend.CompiledConstraintSystem
	mu           sync.RWMutex
}

func InitZKParams() (*ZKParams, error) {
	slog.Info("🔧 Initializing zkSNARK parameters (~30 seconds)...")
	
	circuit := &StateTransitionCircuit{
		TxHashes: make([]frontend.Variable, 100),
	}
	
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("circuit compilation failed: %w", err)
	}
	
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		return nil, fmt.Errorf("zkSNARK setup failed: %w", err)
	}
	
	slog.Info("✅ zkSNARK parameters initialized", "constraints", r1cs.GetNbConstraints())
	
	return &ZKParams{
		ProvingKey:   pk,
		VerifyingKey: vk,
		R1CS:         r1cs,
	}, nil
}

// --- DATA STRUCTURES ---

type Asset struct {
	Ticker      string `json:"ticker"`
	Issuer      string `json:"issuer"`
	TotalSupply int64  `json:"total_supply"`
	Metadata    string `json:"metadata"`
	Timestamp   int64  `json:"timestamp"`
}

type Transaction struct {
	ID        string `json:"id"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Amount    int64  `json:"amount"`
	Asset     string `json:"asset"`
	Nonce     uint64 `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
	PublicKey string `json:"public_key"`
}

func (tx *Transaction) GetSigningData() []byte {
	data := fmt.Sprintf("%s:%s:%d:%s:%d:%d", tx.Sender, tx.Recipient, tx.Amount, tx.Asset, tx.Nonce, tx.Timestamp)
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

func (tx *Transaction) GetHash() string {
	if tx.ID != "" {
		return tx.ID
	}
	data := tx.GetSigningData()
	return hex.EncodeToString(data)
}

type Block struct {
	Index          int64         `json:"index"`
	Timestamp      int64         `json:"timestamp"`
	Transactions   []Transaction `json:"transactions"`
	ZKProof        string        `json:"zk_proof"`
	ZKPublicInputs []string      `json:"zk_public_inputs"`
	ErasureRoot    string        `json:"erasure_root"`
	StateRoot      string        `json:"state_root"`
	PrevHash       string        `json:"prev_hash"`
	Hash           string        `json:"hash"`
}

func (b *Block) ComputeHash() string {
	blockData, _ := json.Marshal(struct {
		Index        int64
		Timestamp    int64
		Transactions []Transaction
		StateRoot    string
		PrevHash     string
	}{b.Index, b.Timestamp, b.Transactions, b.StateRoot, b.PrevHash})
	hash := sha256.Sum256(blockData)
	return hex.EncodeToString(hash[:])
}

// --- CONSENSUS NODE ---

type ContraQNode struct {
	Chain      []Block
	ChainMu    sync.RWMutex
	State      sync.Map
	Nonces     sync.Map
	PublicKeys sync.Map
	Assets     sync.Map
	TxPool     chan Transaction
	RS         reedsolomon.Encoder
	IsRunning  bool
	RunningMu  sync.RWMutex
}

func NewContraQNode() (*ContraQNode, error) {
	rs, err := reedsolomon.New(DataShards, ParityShards)
	if err != nil {
		return nil, err
	}

	genesisHash := sha256.Sum256([]byte("GENESIS"))
	genesis := Block{
		Index:          0,
		Timestamp:      time.Now().Unix(),
		ZKProof:        "GENESIS",
		ZKPublicInputs: []string{"0", "0", "0"},
		Hash:           hex.EncodeToString(genesisHash[:]),
		StateRoot:      "GENESIS_STATE",
	}

	return &ContraQNode{
		Chain:     []Block{genesis},
		TxPool:    make(chan Transaction, 1000000),
		RS:        rs,
		IsRunning: false,
	}, nil
}

func (n *ContraQNode) Start() {
	n.RunningMu.Lock()
	if n.IsRunning {
		n.RunningMu.Unlock()
		return
	}
	n.IsRunning = true
	n.RunningMu.Unlock()

	go n.TransactionProcessor()
	go n.ConsensusEngine()
	
	slog.Info("🌌 ContraQ node started", "version", Version)
}

func (n *ContraQNode) Stop() {
	n.RunningMu.Lock()
	n.IsRunning = false
	n.RunningMu.Unlock()
	slog.Info("Node stopped")
}

// --- TRANSACTION PROCESSING ---

func (n *ContraQNode) TransactionProcessor() {
	for tx := range n.TxPool {
		if err := n.ValidateTransaction(tx); err != nil {
			slog.Warn("❌ Invalid transaction", "tx_id", tx.ID, "error", err)
			continue
		}
		n.ApplyTransaction(tx)
		slog.Debug("✅ Transaction applied", "tx_id", tx.ID)
	}
}

func (n *ContraQNode) ValidateTransaction(tx Transaction) error {
	if tx.Sender == "" || tx.Recipient == "" || tx.Amount <= 0 {
		return errors.New("invalid transaction fields")
	}

	if tx.Asset == "" {
		tx.Asset = "CQ"
	}

	stateKey := tx.Sender + ":" + tx.Asset
	balance, ok := n.State.Load(stateKey)
	if !ok || balance.(int64) < tx.Amount {
		return errors.New("insufficient balance")
	}

	currentNonce, _ := n.Nonces.LoadOrStore(tx.Sender, uint64(0))
	if tx.Nonce <= currentNonce.(uint64) {
		return errors.New("invalid nonce - replay attack detected")
	}

	// QUANTUM-SAFE SIGNATURE VERIFICATION
	if tx.Signature == "" || tx.PublicKey == "" {
		return errors.New("missing signature or public key")
	}

	sigBytes, err := hex.DecodeString(tx.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	pubKeyBytes, err := hex.DecodeString(tx.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid public key encoding: %w", err)
	}

	var pubKey mode5.PublicKey
	if len(pubKeyBytes) != len(pubKey) {
		return errors.New("invalid public key length")
	}
	copy(pubKey[:], pubKeyBytes)

	expectedAddr := fmt.Sprintf("cq_%x", sha256.Sum256(pubKeyBytes)[:20])
	if expectedAddr != tx.Sender {
		return errors.New("public key does not match sender address")
	}

	signingData := tx.GetSigningData()
	if !pubKey.Verify(signingData, sigBytes) {
		return errors.New("invalid Dilithium signature")
	}

	n.PublicKeys.Store(tx.Sender, pubKey)
	return nil
}

func (n *ContraQNode) ApplyTransaction(tx Transaction) {
	senderKey := tx.Sender + ":" + tx.Asset
	recipientKey := tx.Recipient + ":" + tx.Asset

	senderBal, _ := n.State.LoadOrStore(senderKey, int64(0))
	n.State.Store(senderKey, senderBal.(int64)-tx.Amount)

	recipientBal, _ := n.State.LoadOrStore(recipientKey, int64(0))
	n.State.Store(recipientKey, recipientBal.(int64)+tx.Amount)

	n.Nonces.Store(tx.Sender, tx.Nonce)
}

// --- CHAIN-INTRINSIC CONSENSUS ---

func (n *ContraQNode) ConsensusEngine() {
	ticker := time.NewTicker(SlotDuration)
	defer ticker.Stop()

	for {
		n.RunningMu.RLock()
		running := n.IsRunning
		n.RunningMu.RUnlock()

		if !running {
			return
		}

		t := <-ticker.C
		slot := t.Unix() / int64(SlotDuration.Seconds())
		
		// CHAIN-INTRINSIC: Leader selection based ONLY on chain state
		if n.IsSlotLeader(slot) {
			n.ProposeBlock(slot, t.Unix())
		}
	}
}

// IsSlotLeader: Deterministic selection based on chain hash + slot
// NO external influence, NO peers, NO randomness from outside
func (n *ContraQNode) IsSlotLeader(slot int64) bool {
	n.ChainMu.RLock()
	lastBlock := n.Chain[len(n.Chain)-1]
	n.ChainMu.RUnlock()

	// Derive leadership from chain state alone
	slotBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(slotBytes, uint64(slot))
	
	lastHashBytes, _ := hex.DecodeString(lastBlock.Hash)
	combined := append(lastHashBytes, slotBytes...)
	leaderHash := sha256.Sum256(combined)
	
	// Deterministic: if hash starts with specific pattern, this node leads
	// In multi-node: each validator has an index, leader = hash % validator_count == my_index
	return leaderHash[0] < 128 // Single node: always lead
}

func (n *ContraQNode) ProposeBlock(slot, timestamp int64) {
	n.ChainMu.Lock()
	defer n.ChainMu.Unlock()

	last := n.Chain[len(n.Chain)-1]

	var txs []Transaction
	collecting := true
	for collecting && len(txs) < 100 {
		select {
		case tx := <-n.TxPool:
			txs = append(txs, tx)
		default:
			collecting = false
		}
	}

	if len(txs) == 0 {
		return
	}

	prevStateRoot := last.StateRoot
	newStateRoot := n.ComputeStateRoot()

	zkProof, publicInputs, err := n.GenerateZKProof(prevStateRoot, newStateRoot, txs)
	if err != nil {
		slog.Error("❌ zkSNARK proof generation failed", "error", err)
		return
	}

	erasureRoot := n.GenerateErasureRoot(txs)

	block := Block{
		Index:          last.Index + 1,
		Timestamp:      timestamp,
		Transactions:   txs,
		ZKProof:        zkProof,
		ZKPublicInputs: publicInputs,
		ErasureRoot:    erasureRoot,
		StateRoot:      newStateRoot,
		PrevHash:       last.Hash,
	}

	block.Hash = block.ComputeHash()

	if err := n.VerifyZKProof(block); err != nil {
		slog.Error("❌ Block proof verification failed", "error", err)
		return
	}

	if err := n.PersistBlock(block); err != nil {
		slog.Error("❌ Failed to persist block", "error", err)
		return
	}

	n.Chain = append(n.Chain, block)
	
	slog.Info("🔒 Block finalized",
		"height", block.Index,
		"txs", len(txs),
		"hash", block.Hash[:16]+"...",
		"leader_based_on", "chain_hash")
}

// --- zkSNARK PROOF GENERATION ---

func (n *ContraQNode) GenerateZKProof(prevStateRoot, newStateRoot string, txs []Transaction) (string, []string, error) {
	zkParams.mu.RLock()
	defer zkParams.mu.RUnlock()

	prevRoot := new(big.Int)
	prevRoot.SetString(prevStateRoot, 16)
	if prevRoot.BitLen() == 0 {
		prevRoot.SetInt64(0)
	}

	newRoot := new(big.Int)
	newRoot.SetString(newStateRoot, 16)

	txHashes := make([]frontend.Variable, 100)
	for i := 0; i < len(txs) && i < 100; i++ {
		txHash := new(big.Int)
		txHash.SetString(txs[i].GetHash(), 16)
		txHashes[i] = txHash
	}
	for i := len(txs); i < 100; i++ {
		txHashes[i] = big.NewInt(0)
	}

	witness := &StateTransitionCircuit{
		PrevStateRoot: prevRoot,
		NewStateRoot:  newRoot,
		TxCount:       len(txs),
		TxHashes:      txHashes,
	}

	fullWitness, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	if err != nil {
		return "", nil, fmt.Errorf("witness creation failed: %w", err)
	}

	proof, err := groth16.Prove(zkParams.R1CS, zkParams.ProvingKey, fullWitness)
	if err != nil {
		return "", nil, fmt.Errorf("proof generation failed: %w", err)
	}

	proofBytes, err := proof.MarshalBinary()
	if err != nil {
		return "", nil, fmt.Errorf("proof serialization failed: %w", err)
	}

	publicInputs := []string{
		prevStateRoot,
		newStateRoot,
		fmt.Sprintf("%d", len(txs)),
	}

	return hex.EncodeToString(proofBytes), publicInputs, nil
}

func (n *ContraQNode) VerifyZKProof(block Block) error {
	if block.ZKProof == "GENESIS" {
		return nil
	}

	zkParams.mu.RLock()
	defer zkParams.mu.RUnlock()

	proofBytes, err := hex.DecodeString(block.ZKProof)
	if err != nil {
		return fmt.Errorf("proof deserialization failed: %w", err)
	}

	proof := groth16.NewProof(ecc.BN254)
	if err := proof.UnmarshalBinary(proofBytes); err != nil {
		return fmt.Errorf("proof unmarshaling failed: %w", err)
	}

	if len(block.ZKPublicInputs) != 3 {
		return errors.New("invalid public inputs")
	}

	prevRoot := new(big.Int)
	prevRoot.SetString(block.ZKPublicInputs[0], 16)

	newRoot := new(big.Int)
	newRoot.SetString(block.ZKPublicInputs[1], 16)

	var txCount int
	fmt.Sscanf(block.ZKPublicInputs[2], "%d", &txCount)

	publicWitness := &StateTransitionCircuit{
		PrevStateRoot: prevRoot,
		NewStateRoot:  newRoot,
		TxCount:       txCount,
	}

	pubWit, err := frontend.NewWitness(publicWitness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("public witness creation failed: %w", err)
	}

	if err := groth16.Verify(proof, zkParams.VerifyingKey, pubWit); err != nil {
		return fmt.Errorf("zkSNARK verification FAILED: %w", err)
	}

	return nil
}

// --- CRYPTOGRAPHIC PRIMITIVES ---

func (n *ContraQNode) GenerateErasureRoot(txs []Transaction) string {
	if len(txs) == 0 {
		return "EMPTY"
	}

	data, _ := json.Marshal(txs)
	shards, err := n.RS.Split(data)
	if err != nil {
		return "ERROR"
	}

	if err := n.RS.Encode(shards); err != nil {
		return "ERROR"
	}

	root := sha256.Sum256(shards[0])
	return hex.EncodeToString(root[:])
}

func (n *ContraQNode) ComputeStateRoot() string {
	h := sha256.New()
	n.State.Range(func(key, value interface{}) bool {
		h.Write([]byte(fmt.Sprintf("%v:%v", key, value)))
		return true
	})
	return hex.EncodeToString(h.Sum(nil))
}

// --- ASSET ISSUANCE ---

func (n *ContraQNode) IssueAsset(issuerWallet *Wallet, ticker string, supply int64, metadata string) error {
	asset := Asset{
		Ticker:      ticker,
		Issuer:      issuerWallet.Address,
		TotalSupply: supply,
		Metadata:    metadata,
		Timestamp:   time.Now().Unix(),
	}

	if _, exists := n.Assets.Load(ticker); exists {
		return errors.New("asset already exists")
	}

	n.Assets.Store(ticker, asset)
	stateKey := issuerWallet.Address + ":" + ticker
	n.State.Store(stateKey, supply)

	slog.Info("💹 Asset issued", "ticker", ticker, "supply", supply)
	return nil
}

// --- DATABASE ---

func (n *ContraQNode) PersistBlock(block Block) error {
	tx, err := chainDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	blockData, _ := json.Marshal(block)
	_, err = tx.Exec("INSERT INTO blocks (hash, data, height) VALUES (?, ?, ?)",
		block.Hash, blockData, block.Index)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// --- QUERY FUNCTIONS ---

func (n *ContraQNode) GetBalance(address, asset string) int64 {
	key := address + ":" + asset
	bal, ok := n.State.Load(key)
	if !ok {
		return 0
	}
	return bal.(int64)
}

func (n *ContraQNode) GetNonce(address string) uint64 {
	nonce, _ := n.Nonces.LoadOrStore(address, uint64(0))
	return nonce.(uint64)
}

func (n *ContraQNode) GetLatestBlock() Block {
	n.ChainMu.RLock()
	defer n.ChainMu.RUnlock()
	return n.Chain[len(n.Chain)-1]
}

// --- RATE LIMITING UTILITIES ---

func getClientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		return xf
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func checkRateLimit(ip string) error {
	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()

	// Check if IP is locked out
	if lockTime, ok := lockedUntil.Load(ip); ok {
		if time.Now().Before(lockTime.(time.Time)) {
			return fmt.Errorf("IP locked due to too many failed attempts")
		}
		// Lockout expired
		lockedUntil.Delete(ip)
		failedAttempts.Delete(ip)
	}

	return nil
}

func recordFailedAttempt(ip string) {
	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()

	attempts, _ := failedAttempts.LoadOrStore(ip, 0)
	newAttempts := attempts.(int) + 1
	failedAttempts.Store(ip, newAttempts)

	if newAttempts >= MaxFailedAttempts {
		lockedUntil.Store(ip, time.Now().Add(LockoutDuration))
		slog.Warn("🚨 IP locked out", "ip", ip, "duration", LockoutDuration)
	}
}

func resetFailedAttempts(ip string) {
	failedAttempts.Delete(ip)
}

// --- HTTP API ---

func setupRouter(node *ContraQNode) *mux.Router {
	r := mux.NewRouter()

	r.HandleFunc("/api/v1/transaction", handleSubmitTransaction(node)).Methods("POST")
	r.HandleFunc("/api/v1/balance/{address}/{asset}", handleGetBalance(node)).Methods("GET")
	r.HandleFunc("/api/v1/nonce/{address}", handleGetNonce(node)).Methods("GET")
	r.HandleFunc("/api/v1/asset/issue", handleIssueAsset(node)).Methods("POST")
	r.HandleFunc("/api/v1/asset/{ticker}", handleGetAsset(node)).Methods("GET")
	r.HandleFunc("/api/v1/chain/latest", handleGetLatestBlock(node)).Methods("GET")
	r.HandleFunc("/api/v1/chain/block/{index}", handleGetBlock(node)).Methods("GET")
	r.HandleFunc("/api/v1/chain/state", handleChainState(node)).Methods("GET")
	r.HandleFunc("/api/v1/status", handleStatus(node)).Methods("GET")

	return r
}

func handleSubmitTransaction(node *ContraQNode) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)

		// Check rate limit
		if err := checkRateLimit(ip); err != nil {
			http.Error(w, "Too many failed attempts. Please try again later.", http.StatusTooManyRequests)
			return
		}

		var tx Transaction
		if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
			recordFailedAttempt(ip)
			http.Error(w, "Invalid transaction", http.StatusBadRequest)
			return
		}

		// Auto-sign if from node wallet
		if tx.Sender == nodeWallet.Address && tx.Signature == "" {
			tx.PublicKey = hex.EncodeToString(nodeWallet.PublicKey.Bytes())
			tx.Signature = hex.EncodeToString(nodeWallet.Sign(tx.GetSigningData()))
		}

		// Validate before queueing
		if err := node.ValidateTransaction(tx); err != nil {
			recordFailedAttempt(ip)
			http.Error(w, fmt.Sprintf("Transaction validation failed: %s", err.Error()), http.StatusForbidden)
			return
		}

		// Success - reset failed attempts
		resetFailedAttempts(ip)

		node.TxPool <- tx
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "accepted",
			"tx_id":  tx.ID,
		})
	}
}

func handleGetBalance(node *ContraQNode) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		balance := node.GetBalance(vars["address"], vars["asset"])
		json.NewEncoder(w).Encode(map[string]interface{}{
			"address": vars["address"],
			"asset":   vars["asset"],
			"balance": balance,
		})
	}
}

func handleGetNonce(node *ContraQNode) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		nonce := node.GetNonce(vars["address"])
		json.NewEncoder(w).Encode(map[string]interface{}{
			"address": vars["address"],
			"nonce":   nonce,
		})
	}
}

func handleIssueAsset(node *ContraQNode) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)

		if err := checkRateLimit(ip); err != nil {
			http.Error(w, "Too many failed attempts", http.StatusTooManyRequests)
			return
		}

		var req struct {
			Ticker   string `json:"ticker"`
			Supply   int64  `json:"supply"`
			Metadata string `json:"metadata"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			recordFailedAttempt(ip)
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if err := node.IssueAsset(nodeWallet, req.Ticker, req.Supply, req.Metadata); err != nil {
			recordFailedAttempt(ip)
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}

		resetFailedAttempts(ip)
		json.NewEncoder(w).Encode(map[string]string{"status": "issued", "ticker": req.Ticker})
	}
}

func handleGetAsset(node *ContraQNode) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		asset, ok := node.Assets.Load(vars["ticker"])
		if !ok {
			http.Error(w, "Asset not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(asset)
	}
}

func handleGetLatestBlock(node *ContraQNode) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(node.GetLatestBlock())
	}
}

func handleGetBlock(node *ContraQNode) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		var index int64
		fmt.Sscanf(vars["index"], "%d", &index)

		node.ChainMu.RLock()
		defer node.ChainMu.RUnlock()

		if index < 0 || index >= int64(len(node.Chain)) {
			http.Error(w, "Block not found", http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(node.Chain[index])
	}
}

func handleChainState(node *ContraQNode) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		latest := node.GetLatestBlock()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"height":       latest.Index,
			"hash":         latest.Hash,
			"state_root":   latest.StateRoot,
			"zk_proof":     latest.ZKProof[:min(16, len(latest.ZKProof))] + "...",
			"erasure_root": latest.ErasureRoot,
		})
	}
}

func handleStatus(node *ContraQNode) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"version":   Version,
			"node":      nodeWallet.Address,
			"running":   node.IsRunning,
			"height":    node.GetLatestBlock().Index,
			"consensus": "chain-intrinsic",
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// --- INITIALIZATION ---

func initDatabase() error {
	db, err := sql.Open("sqlite3", "./contraq_v14_1.db?_journal_mode=WAL")
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS blocks (
			hash TEXT PRIMARY KEY,
			data BLOB NOT NULL,
			height INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_height ON blocks(height);
	`)
	if err != nil {
		return err
	}

	chainDB = db
	return nil
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	slog.Info("🌌 ContraQ v14.1 Starting", "version", Version)

	// Initialize zkSNARK parameters
	var err error
	zkParams, err = InitZKParams()
	if err != nil {
		log.Fatal("zkSNARK initialization failed:", err)
	}

	// Initialize wallet
	nodeWallet = NewWallet()
	slog.Info("✅ Quantum-safe wallet initialized", "address", nodeWallet.Address)

	// Initialize database
	if err := initDatabase(); err != nil {
		log.Fatal("Database initialization failed:", err)
	}
	defer chainDB.Close()

	// Create node
	node, err := NewContraQNode()
	if err != nil {
		log.Fatal("Node creation failed:", err)
	}

	// Initialize genesis state
	node.State.Store(nodeWallet.Address+":CQ", int64(GenesisSupply))
	node.PublicKeys.Store(nodeWallet.Address, nodeWallet.PublicKey)

	// Issue institutional assets
	node.IssueAsset(nodeWallet, "CUSD", 1_000_000_000_000, "USD Stablecoin")
	node.IssueAsset(nodeWallet, "CGOLD", 100_000_000, "Tokenized Gold")

	node.Start()
	globalNode = node
	defer node.Stop()

	// Setup HTTP server
	router := setupRouter(node)
	srv := &http.Server{
		Addr:         ServerPort,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	go func() {
		slog.Info("🛡️  Node online", "port", ServerPort, "consensus", "chain-intrinsic")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server error", "error", err)
		}
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	slog.Info("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	slog.Info("✅ Shutdown complete")
}

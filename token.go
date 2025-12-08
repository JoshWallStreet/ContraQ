package main

import (
	"encoding/hex"
	"fmt"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"sync"
)

// ContraQoinManager handles the token economy logic
type ContraQoinManager struct {
	TotalSupply int64
	Balances    map[string]int64
	mu          sync.Mutex
}

// Global coin manager instance
var CQ = ContraQoinManager{
	TotalSupply: 1000000000, // 1 Billion ContraQoin
	Balances:    make(map[string]int64),
}

// Transfer tokens only if valid PQC signature is provided
func (c *ContraQoinManager) Transfer(sender, receiver string, amount int64, signature, message string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 1. Check Balances
	if c.Balances[sender] < amount {
		return fmt.Errorf("insufficient ContraQoin balance")
	}

	// 2. Post-Quantum Signature Verification (The Secure Backstop)
	pkBytes, _ := hex.DecodeString(sender)
	var pk mode3.PublicKey
	pk.UnmarshalBinary(pkBytes)
	sig, _ := hex.DecodeString(signature)

	if !mode3.Verify(&pk, []byte(message), sig) {
		return fmt.Errorf("transaction verification failed: unauthorized quantum identity")
	}

	// 3. Execute State Update
	c.Balances[sender] -= amount
	c.Balances[receiver] += amount
	return nil
}

// InitialDistribution grants tokens to the genesis address
func (c *ContraQoinManager) InitialDistribution(genesisAddress string) {
	c.Balances[genesisAddress] = c.TotalSupply
}

package main

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

const keystoreFile = "keystore.json"

func clientIPFromRequest(r *http.Request) string {
	// prefer X-Forwarded-For if present (e.g., behind proxy); otherwise use remote addr
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		return xf
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func main() {
	// 1) Load blockchain (existing logic)
	LoadBlockchain()

	// 2) Wire up HTTP router
	r := mux.NewRouter()

	// Blockchain endpoints (existing)
	r.HandleFunc("/blockchain", GetBlockchain).Methods("GET")
	r.HandleFunc("/create-transaction", CreateTransaction).Methods("POST")
	r.HandleFunc("/mine-block", MineBlock).Methods("POST")

	// 3) Wallet endpoints (keystore)
	WireWalletHandlers(r)

	// 4) Brute-force / admin endpoints are provided by the merged main.go earlier
	//        (status endpoint remains available via /status if desired)
	r.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		backoffMutex.Lock()
		defer backoffMutex.Unlock()
		type entry struct {
			IP     string `json:"ip"`
			Count  int    `json:"count"`
			Locked string `json:"locked_until"`
		}
		var out []entry
		for ip, be := range backoffMap {
			out = append(out, entry{IP: ip, Count: be.Count, Locked: be.LockedUntil.Format("2006-01-02T15:04:05Z")})
		}
		json.NewEncoder(w).Encode(struct {
			ChainLen int     `json:"chain_length"`
			Backoff  []entry `json:"backoff"`
		}{ChainLen: len(BC.Chain), Backoff: out})
	}).Methods("GET")

	// 5) Startup message & run
	log.Println("🚀 ContraQ node (merged) running on 127.0.0.1:8080")
	pass := os.Getenv("CONTRAQ_PASSPHRASE")
	if pass == "" {
		log.Println("WARNING: CONTRAQ_PASSPHRASE not set — use environment variable in production.")
	}
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", r))
}

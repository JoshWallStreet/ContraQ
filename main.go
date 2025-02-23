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
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/gorilla/mux"
)

// Blockchain state
type Blockchain struct {
	Chain        []Block
	PendingTx    []Transaction
	Wallets      []*Wallet
	mutex        sync.Mutex
}

// Block structure
type Block struct {
	Index        int           `json:"index"`
	Timestamp    string        `json:"timestamp"`
	Transactions []Transaction `json:"transactions"`
	PreviousHash string        `json:"previousHash"`
	Hash         string        `json:"hash"`
	Validator    string        `json:"validator"`
}

// Transaction structure
type Transaction struct {
	Sender    string `json:"sender"`
	Receiver  string `json:"receiver"`
	Amount    int    `json:"amount"`
	Signature string `json:"signature"`
}

// Wallet structure (Quantum-Safe)
type Wallet struct {
	Address    string            `json:"address"`
	Balance    int               `json:"balance"`
	Stake      int               `json:"stake"`
	PrivateKey *mode3.PrivateKey `json:"-"`
	PublicKey  *mode3.PublicKey  `json:"-"`
}

const (
	genesisData = "genesis-block"
	reward      = 10
)

var bc = Blockchain{}
var blockchainFile = "blockchain.json"

func init() {
	loadBlockchain()
	if len(bc.Chain) == 0 {
		createGenesisBlock()
	}
}

func createGenesisBlock() {
	genesis := Block{
		Index:        0,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Transactions: []Transaction{},
		PreviousHash: "0",
		Validator:    genesisData,
	}
	genesis.Hash = calculateHash(genesis)
	bc.Chain = append(bc.Chain, genesis)
	saveBlockchain()
}

func calculateHash(b Block) string {
	data := fmt.Sprintf("%d%s%v%s%s", 
		b.Index, b.Timestamp, b.Transactions, b.PreviousHash, b.Validator)
	hash := mode3.Hash([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (bc *Blockchain) GenerateWallet() *Wallet {
	privateKey, publicKey, _ := mode3.GenerateKey(nil)
	wallet := &Wallet{
		Address:    hex.EncodeToString(publicKey.Bytes())[:12],
		Balance:    1000,
		Stake:      0,
		PrivateKey: privateKey,

go mod init github.com/JoshWallStreet/ContraQ || true

rm -rf go.sum

bash: export: Files/Go/bin:/cmd:/c/Users/pavli/AppData/Local/Programs/Python/Python313/Scripts:/c/Users/pavli/AppData/Local/Programs/Python/Python313:/c/Users/pavli/AppData/Local/Microsoft/WindowsApps:/c/Users/pavli/go/bin:/usr/bin/vendor_perl:/usr/bin/core_perl:C:Userspavligo/bin': not a valid identifier

joshwallstreet@DESKTOP-COD4LKE MINGW64 ~
$ go mod init quantum-blockchain
go mod tidy
bash: go: command not found
bash: go: command not found

joshwallstreet@DESKTOP-COD4LKE MINGW64 ~
$ cd ~/PAVLI/NEW FOLDER/MAIN.GO
bash: cd: too many arguments

joshwallstreet@DESKTOP-COD4LKE MINGW64 ~
$ cd ~/ContraQ

joshwallstreet@DESKTOP-COD4LKE MINGW64 ~/ContraQ
$ git init
Initialized empty Git repository in C:/Users/pavli/ContraQ/.git/

joshwallstreet@DESKTOP-COD4LKE MINGW64 ~/ContraQ (master)
$ git remote add origin https://github.com/JoshWallStreet/ContraQ

joshwallstreet@DESKTOP-COD4LKE MINGW64 ~/ContraQ (master)
$ git add main.go
warning: in the working copy of 'main.go', LF will be replaced by CRLF the next time Git touches it

joshwallstreet@DESKTOP-COD4LKE MINGW64 ~/ContraQ (master)
$ git commit -m "🚀 Initial commit - Quantum Blockchain (PoS & Quantum-Safe Wallets)"
[master (root-commit) 88c351f] 🚀 Initial commit - Quantum Blockchain (PoS & Quantum-Safe Wallets)
 1 file changed, 235 insertions(+)
 create mode 100644 main.go

joshwallstreet@DESKTOP-COD4LKE MINGW64 ~/ContraQ (master)
$ git branch -M main

joshwallstreet@DESKTOP-COD4LKE MINGW64 ~/ContraQ (main)
$ git push -u origin main
To https://github.com/JoshWallStreet/ContraQ
 ! [rejected]        main -> main (fetch first)
error: failed to push some refs to 'https://github.com/JoshWallStreet/ContraQ'
hint: Updates were rejected because the remote contains work that you do not
hint: have locally. This is usually caused by another repository pushing to
hint: the same ref. If you want to integrate the remote changes, use
hint: 'git pull' before pushing again.
hint: See the 'Note about fast-forwards' in 'git push --help' for details.

joshwallstreet@DESKTOP-COD4LKE MINGW64 ~/ContraQ (main)
$ git push --force origin main
Enumerating objects: 3, done.
Counting objects: 100% (3/3), done.
Delta compression using up to 4 threads
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 2.34 KiB | 2.34 MiB/s, done.
Total 3 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
To https://github.com/JoshWallStreet/ContraQ
 + d49c8f3...88c351f main -> main (forced update)

joshwallstreet@DESKTOP-COD4LKE MINGW64 ~/ContraQ (main)
$ git log --oneline --graph --decorate --all
* 88c351f (HEAD -> main, origin/main) 🚀 Initial commit - Quantum Blockchain (PoS & Quantum-Safe Wallets)

joshwallstreet@DESKTOP-COD4LKE MINGW64 ~/ContraQ (main)
$ git clone https://github.com/JoshWallStreet/ContraQ.git
cd ContraQ
ls
fatal: destination path 'ContraQ' already exists and is not an empty directory.
bash: cd: ContraQ: Not a directory
ContraQ  go  go.mod  go.sum  main.go

joshwallstreet@DESKTOP-COD4LKE MINGW64 ~/ContraQ (main)
$ ssh root@96.30.197.197
cd /root/ContraQ
git pull origin main
go run main.go
root@96.30.197.197's password:
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-131-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Feb 23 08:28:43 AM UTC 2025

  System load:  0.0                Processes:               121
  Usage of /:   21.8% of 51.01GB   Users logged in:         0
  Memory usage: 15%                IPv4 address for enp1s0: 96.30.197.197
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

9 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

New release '24.04.2 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


Last login: Sun Feb 23 06:43:23 2025 from 35.33.217.26
root@vultr:~# apt update && apt upgrade -y
Hit:1 http://ubuntu.mirror.constant.com jammy InRelease
Hit:2 http://archive.ubuntu.com/ubuntu jammy InRelease
Get:3 http://ubuntu.mirror.constant.com jammy-updates InRelease [128 kB]
Get:4 http://archive.ubuntu.com/ubuntu jammy-updates InRelease [128 kB]
Get:5 http://ubuntu.mirror.constant.com jammy-backports InRelease [127 kB]
Get:6 http://archive.ubuntu.com/ubuntu jammy-backports InRelease [127 kB]
Get:7 http://ubuntu.mirror.constant.com jammy-security InRelease [129 kB]
Get:8 http://archive.ubuntu.com/ubuntu jammy-security InRelease [129 kB]
Get:9 http://ubuntu.mirror.constant.com jammy-updates/main amd64 Packages [2,339 kB]
Get:10 http://ubuntu.mirror.constant.com jammy-updates/universe amd64 Packages [1,187 kB]
Get:11 http://ubuntu.mirror.constant.com jammy-backports/universe amd64 Packages [30.0 kB]
Get:12 http://ubuntu.mirror.constant.com jammy-backports/universe Translation-en [16.6 kB]
Get:13 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 Packages [2,339 kB]
Get:14 http://archive.ubuntu.com/ubuntu jammy-updates/universe amd64 Packages [1,187 kB]
Get:15 http://archive.ubuntu.com/ubuntu jammy-backports/universe amd64 Packages [30.0 kB]
Get:16 http://archive.ubuntu.com/ubuntu jammy-backports/universe Translation-en [16.6 kB]
Fetched 7,914 kB in 3s (2,268 kB/s)
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
7 packages can be upgraded. Run 'apt list --upgradable' to see them.
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
Calculating upgrade... Done
The following NEW packages will be installed:
  linux-headers-5.15.0-133 linux-headers-5.15.0-133-generic
  linux-image-5.15.0-133-generic linux-modules-5.15.0-133-generic
  linux-modules-extra-5.15.0-133-generic
The following packages have been kept back:
  landscape-common
The following packages will be upgraded:
  libldap-2.5-0 libldap-common linux-generic linux-headers-generic
  linux-image-generic linux-libc-dev
6 upgraded, 5 newly installed, 0 to remove and 1 not upgraded.
Need to get 115 MB of archives.
After this operation, 584 MB of additional disk space will be used.
Get:1 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 libldap-2.5-0 amd64 2.5.18+dfsg-0ubuntu0.22.04.3 [183 kB]
Get:2 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 libldap-common all 2.5.18+dfsg-0ubuntu0.22.04.3 [15.8 kB]
Get:3 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 linux-modules-5.15.0-133-generic amd64 5.15.0-133.144 [22.7 MB]
Get:4 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 linux-image-5.15.0-133-generic amd64 5.15.0-133.144 [11.6 MB]
Get:5 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 linux-modules-extra-5.15.0-133-generic amd64 5.15.0-133.144 [63.9 MB]
Get:6 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 linux-generic amd64 5.15.0.133.132 [1,698 B]
Get:7 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 linux-image-generic amd64 5.15.0.133.132 [2,514 B]
Get:8 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 linux-headers-5.15.0-133 all 5.15.0-133.144 [12.3 MB]
Get:9 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 linux-headers-5.15.0-133-generic amd64 5.15.0-133.144 [2,831 kB]
Get:10 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 linux-headers-generic amd64 5.15.0.133.132 [2,372 B]
Get:11 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 linux-libc-dev amd64 5.15.0-133.144 [1,298 kB]
Fetched 115 MB in 2s (60.2 MB/s)
(Reading database ... 134392 files and directories currently installed.)
Preparing to unpack .../00-libldap-2.5-0_2.5.18+dfsg-0ubuntu0.22.04.3_amd64.deb ...
Unpacking libldap-2.5-0:amd64 (2.5.18+dfsg-0ubuntu0.22.04.3) over (2.5.18+dfsg-0ubuntu0.22.04.2) ...
Preparing to unpack .../01-libldap-common_2.5.18+dfsg-0ubuntu0.22.04.3_all.deb ...

go get github.com/gorilla/mux

go mod tidy

cat <<EOF > main.go
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
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/gorilla/mux"
)

// Blockchain state
type Blockchain struct {
	Chain     []Block
	PendingTx []Transaction
	Wallets   []*Wallet
	mutex     sync.Mutex
}

// Block structure
type Block struct {
	Index        int           `json:"index"`
	Timestamp    string        `json:"timestamp"`
	Transactions []Transaction `json:"transactions"`
	PreviousHash string        `json:"previousHash"`
	Hash         string        `json:"hash"`
	Validator    string        `json:"validator"`
}

// Transaction structure
type Transaction struct {
	Sender    string `json:"sender"`
	Receiver  string `json:"receiver"`
	Amount    int    `json:"amount"`
	Signature string `json:"signature"`
}

// Wallet structure (Quantum-Safe)
type Wallet struct {
	Address    string             `json:"address"`
	Balance    int                `json:"balance"`
	Stake      int                `json:"stake"`
	PrivateKey *mode3.PrivateKey  `json:"-"`
	PublicKey  *mode3.PublicKey   `json:"-"`
}

const (
	genesisData = "genesis-block"
	reward      = 10
)

var bc = Blockchain{}
var blockchainFile = "blockchain.json"

func init() {
	loadBlockchain()
	if len(bc.Chain) == 0 {
		createGenesisBlock()
	}
}

func createGenesisBlock() {
	genesis := Block{
		Index:        0,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Transactions: []Transaction{},
		PreviousHash: "0",
		Validator:    genesisData,
	}
	genesis.Hash = calculateHash(genesis)
	bc.Chain = append(bc.Chain, genesis)
	saveBlockchain()
}

func calculateHash(b Block) string {
	data := fmt.Sprintf("%d%s%v%s%s", b.Index, b.Timestamp, b.Transactions, b.PreviousHash, b.Validator)
	hash := mode3.New().Hash([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (bc *Blockchain) GenerateWallet() *Wallet {
	privateKey, publicKey, _ := mode3.GenerateKey(nil)
	wallet := &Wallet{
		Address:    hex.EncodeToString(publicKey.Bytes())[:12],
		Balance:    1000,
		Stake:      0,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}
	bc.mutex.Lock()
	bc.Wallets = append(bc.Wallets, wallet)
	bc.mutex.Unlock()
	return wallet
}

func (w *Wallet) SignTransaction(tx *Transaction) error {
	msg := []byte(fmt.Sprintf("%s%s%d", tx.Sender, tx.Receiver, tx.Amount))
	signature, err := w.PrivateKey.Sign(rand.Reader, msg, nil)
	if err != nil {
		return err
	}
	tx.Signature = hex.EncodeToString(signature)
	return nil
}

func (bc *Blockchain) VerifyTransaction(tx Transaction) bool {
	sender := bc.FindWallet(tx.Sender)
	if sender == nil || sender.Balance < tx.Amount {
		return false
	}

	msg := []byte(fmt.Sprintf("%s%s%d", tx.Sender, tx.Receiver, tx.Amount))
	signature, _ := hex.DecodeString(tx.Signature)

	return mode3.Verify(sender.PublicKey, msg, signature) == nil
}

func (bc *Blockchain) FindWallet(address string) *Wallet {
	for _, w := range bc.Wallets {
		if w.Address == address {
			return w
		}
	}
	return nil
}

func (bc *Blockchain) MineBlock() {
	if len(bc.PendingTx) == 0 {
		return
	}

	validator := bc.SelectValidator()
	newBlock := Block{
		Index:        len(bc.Chain),
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Transactions: bc.PendingTx,
		PreviousHash: bc.Chain[len(bc.Chain)-1].Hash,
		Validator:    validator.Address,
	}
	newBlock.Hash = calculateHash(newBlock)

	bc.mutex.Lock()
	bc.Chain = append(bc.Chain, newBlock)
	validator.Balance += reward
	bc.PendingTx = nil
	bc.mutex.Unlock()
	saveBlockchain()
}

func (bc *Blockchain) SelectValidator() *Wallet {
	totalStake := 0
	for _, w := range bc.Wallets {
		totalStake += w.Stake
	}

	randStake, _ := rand.Int(rand.Reader, big.NewInt(int64(totalStake)))
	for _, w := range bc.Wallets {
		randStake.Sub(randStake, big.NewInt(int64(w.Stake)))
		if randStake.Sign() <= 0 {
			return w
		}
	}
	return bc.Wallets[0]
}

func saveBlockchain() {
	data, _ := json.Marshal(bc.Chain)
	os.WriteFile(blockchainFile, data, 0644)
}

func loadBlockchain() {
	data, err := os.ReadFile(blockchainFile)
	if err != nil {
		return
	}
	json.Unmarshal(data, &bc.Chain)
}

func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		next.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()
	r.Use(enableCORS)

	r.HandleFunc("/blockchain", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(bc.Chain)
	}).Methods("GET")

	r.HandleFunc("/wallet", func(w http.ResponseWriter, r *http.Request) {
		wallet := bc.GenerateWallet()
		json.NewEncoder(w).Encode(wallet)
	}).Methods("POST")

	r.HandleFunc("/transaction", func(w http.ResponseWriter, r *http.Request) {
		var tx Transaction
		_ = json.NewDecoder(r.Body).Decode(&tx)

		if bc.VerifyTransaction(tx) {
			bc.mutex.Lock()
			bc.PendingTx = append(bc.PendingTx, tx)
			sender := bc.FindWallet(tx.Sender)
			receiver := bc.FindWallet(tx.Receiver)
			sender.Balance -= tx.Amount
			receiver.Balance += tx.Amount
			bc.mutex.Unlock()
			json.NewEncoder(w).Encode("Transaction added!")
		} else {
			json.NewEncoder(w).Encode("Transaction failed!")
		}
	}).Methods("POST")

	r.HandleFunc("/mine", func(w http.ResponseWriter, r *http.Request) {
		bc.MineBlock()
		json.NewEncoder(w).Encode("Block mined successfully!")
	}).Methods("POST")

	fmt.Println("🚀 Blockchain server running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

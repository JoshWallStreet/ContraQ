package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode5"
)

const addressPrefix = "cq_"

type result struct {
	Address     string
	SeedHex     string
	PublicKey   string
	PrivateKey  string
	Attempts    uint64
	Elapsed     time.Duration
	RatePerSec  float64
	WorkerCount int
}

func main() {
	prefix := flag.String("prefix", "", "required address prefix to match after cq_")
	suffix := flag.String("suffix", "", "optional address suffix to match")
	workers := flag.Int("workers", runtime.NumCPU(), "number of concurrent workers")
	limit := flag.Uint64("limit", 0, "maximum attempts before stopping (0 = unlimited)")
	timeout := flag.Duration("timeout", 30*time.Second, "maximum search time")
	flag.Parse()

	normalizedPrefix := normalizeConstraint(*prefix)
	normalizedSuffix := normalizeConstraint(*suffix)
	if normalizedPrefix == "" && normalizedSuffix == "" {
		log.Fatal("set -prefix, -suffix, or both")
	}
	if *workers < 1 {
		log.Fatal("workers must be at least 1")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	started := time.Now()
	match, err := searchVanityAddress(ctx, normalizedPrefix, normalizedSuffix, *workers, *limit)
	if err != nil {
		log.Fatalf("search failed: %v", err)
	}

	fmt.Println("ContraQ vanity generator")
	fmt.Println("------------------------")
	fmt.Printf("Constraint: prefix=%q suffix=%q\n", normalizedPrefix, normalizedSuffix)
	fmt.Printf("Workers: %d\n", match.WorkerCount)
	fmt.Printf("Attempts: %d\n", match.Attempts)
	fmt.Printf("Elapsed: %s\n", match.Elapsed.Round(time.Millisecond))
	fmt.Printf("Throughput: %.2f keys/sec\n", match.RatePerSec)
	fmt.Printf("Completed at: %s\n", started.Add(match.Elapsed).Format(time.RFC3339))
	fmt.Println()
	fmt.Printf("Address:    %s\n", match.Address)
	fmt.Printf("Seed:       %s\n", match.SeedHex)
	fmt.Printf("Public key: %s\n", match.PublicKey)
	fmt.Printf("Private key:%s\n", match.PrivateKey)
}

func searchVanityAddress(ctx context.Context, prefix, suffix string, workers int, limit uint64) (*result, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var attempts atomic.Uint64
	results := make(chan result, 1)
	var wg sync.WaitGroup
	started := time.Now()

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				attempt := attempts.Add(1)
				if limit > 0 && attempt > limit {
					cancel()
					return
				}

				seed, address, pub, priv, err := generateCandidate()
				if err != nil {
					continue
				}
				if !matchesConstraint(address, prefix, suffix) {
					continue
				}

				elapsed := time.Since(started)
				keysPerSec := float64(attempt) / elapsed.Seconds()
				select {
				case results <- result{
					Address:     address,
					SeedHex:     hex.EncodeToString(seed[:]),
					PublicKey:   hex.EncodeToString(pub),
					PrivateKey:  hex.EncodeToString(priv),
					Attempts:    attempt,
					Elapsed:     elapsed,
					RatePerSec:  keysPerSec,
					WorkerCount: workers,
				}:
					cancel()
				case <-ctx.Done():
				}
				return
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case match := <-results:
		<-done
		return &match, nil
	case <-done:
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%w after %d attempts", err, attempts.Load())
		}
		return nil, fmt.Errorf("search stopped after %d attempts", attempts.Load())
	case <-ctx.Done():
		<-done
		return nil, fmt.Errorf("%w after %d attempts", ctx.Err(), attempts.Load())
	}
}

func generateCandidate() ([32]byte, string, []byte, []byte, error) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return seed, "", nil, nil, err
	}
	priv, pub := mode5.NewKeyFromSeed(&seed)
	address := deriveAddress(pub.Bytes())
	return seed, address, pub.Bytes(), priv.Bytes(), nil
}

func deriveAddress(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return addressPrefix + hex.EncodeToString(sum[:20])
}

func matchesConstraint(address, prefix, suffix string) bool {
	trimmed := strings.TrimPrefix(strings.ToLower(address), addressPrefix)
	return strings.HasPrefix(trimmed, prefix) && strings.HasSuffix(trimmed, suffix)
}

func normalizeConstraint(value string) string {
	cleaned := strings.ToLower(strings.TrimSpace(value))
	cleaned = strings.TrimPrefix(cleaned, addressPrefix)
	return cleaned
}

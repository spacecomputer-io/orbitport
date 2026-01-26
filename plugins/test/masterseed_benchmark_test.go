package e2e

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/plugin/masterseed"
)

// generateTestSeed returns a valid 32-byte hex seed for testing.
func generateTestSeed(b *testing.B) string {
	b.Helper()

	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	if err != nil {
		b.Fatalf("rand.Read failed: %v", err)
	}
	return hex.EncodeToString(raw)
}

// Benchmark deriving a single output (TRNGSize bytes) from a seed block.
// This exercises: hex decode + ChaCha expansion + hex encode.
func BenchmarkDeriveSingle(b *testing.B) {
	seedHex := generateTestSeed(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := masterseed.DeriveOneFromSeedHex(seedHex)
		if err != nil {
			b.Fatalf("derivation failed: %v", err)
		}
	}
}

// Benchmark deriving a single output using the nonce mode (unique per call).
// This exercises: hex decode + SHA256(seed||nonce||seq) + ChaCha expansion + hex encode.
func BenchmarkDeriveSingle_WithNonce(b *testing.B) {
	seedHex := generateTestSeed(b)
	ms := masterseed.MasterSeed{Seed: seedHex}

	nonce := time.Now().UnixNano()
	var seq uint64

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq++
		_, err := ms.DeriveBulkWithNonce(1, nonce, seq)
		if err != nil {
			b.Fatalf("derivation failed: %v", err)
		}
	}
}

// Benchmark Bulk Derivation (Small Batch - 10)
func BenchmarkDeriveBulk_10(b *testing.B) {
	seedHex := generateTestSeed(b)
	ms := masterseed.MasterSeed{Seed: seedHex}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ms.DeriveBulk(10)
		if err != nil {
			b.Fatalf("bulk derivation 10 failed: %v", err)
		}
	}
}

func BenchmarkDeriveBulkWithNonce_10(b *testing.B) {
	seedHex := generateTestSeed(b)
	ms := masterseed.MasterSeed{Seed: seedHex}

	nonce := time.Now().UnixNano()
	var seq uint64

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq++
		_, err := ms.DeriveBulkWithNonce(10, nonce, seq)
		if err != nil {
			b.Fatalf("bulk derivation with nonce 10 failed: %v", err)
		}
	}
}

// Benchmark Bulk Derivation (Large Batch - 100)
func BenchmarkDeriveBulk_100(b *testing.B) {
	seedHex := generateTestSeed(b)
	ms := masterseed.MasterSeed{Seed: seedHex}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ms.DeriveBulk(100)
		if err != nil {
			b.Fatalf("bulk derivation 100 failed: %v", err)
		}
	}
}

func BenchmarkDeriveBulkWithNonce_100(b *testing.B) {
	seedHex := generateTestSeed(b)
	ms := masterseed.MasterSeed{Seed: seedHex}

	nonce := time.Now().UnixNano()
	var seq uint64

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq++
		_, err := ms.DeriveBulkWithNonce(100, nonce, seq)
		if err != nil {
			b.Fatalf("bulk derivation with nonce 100 failed: %v", err)
		}
	}
}

// Benchmark Bulk Derivation (XLarge Batch - 1000)
func BenchmarkDeriveBulk_1000(b *testing.B) {
	seedHex := generateTestSeed(b)
	ms := masterseed.MasterSeed{Seed: seedHex}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ms.DeriveBulk(1000)
		if err != nil {
			b.Fatalf("bulk derivation 1000 failed: %v", err)
		}
	}
}

func BenchmarkDeriveBulkWithNonce_1000(b *testing.B) {
	seedHex := generateTestSeed(b)
	ms := masterseed.MasterSeed{Seed: seedHex}

	nonce := time.Now().UnixNano()
	var seq uint64

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq++
		_, err := ms.DeriveBulkWithNonce(1000, nonce, seq)
		if err != nil {
			b.Fatalf("bulk derivation with nonce 1000 failed: %v", err)
		}
	}
}

// Benchmark Bulk Derivation (XXLarge Batch - 100000)
// Consider running it manually with `-run=^$ -bench=BenchmarkDeriveBulk_100000 -benchtime=1x`.
func BenchmarkDeriveBulk_100000(b *testing.B) {
	seedHex := generateTestSeed(b)
	ms := masterseed.MasterSeed{Seed: seedHex}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ms.DeriveBulk(100000)
		if err != nil {
			b.Fatalf("bulk derivation 100000 failed: %v", err)
		}
	}
}

func BenchmarkDeriveBulkWithNonce_100000(b *testing.B) {
	seedHex := generateTestSeed(b)
	ms := masterseed.MasterSeed{Seed: seedHex}

	nonce := time.Now().UnixNano()
	var seq uint64

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq++
		_, err := ms.DeriveBulkWithNonce(100000, nonce, seq)
		if err != nil {
			b.Fatalf("bulk derivation with nonce 100000 failed: %v", err)
		}
	}
}

package e2e

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/plugin/masterseed"
)

// Generate a valid 32-byte hex seed for testing
func generateTestSeed() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Benchmark single derivation
func BenchmarkDeriveSingle(b *testing.B) {
	seedHex := generateTestSeed()
	ms := masterseed.MasterSeed{Seed: seedHex}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ms.Derive(uint32(i % 100000))
		if err != nil {
			b.Fatalf("derivation failed: %v", err)
		}
	}
}

// Benchmark Bulk Derivation (Small Batch - 10)
func BenchmarkDeriveBulk_10(b *testing.B) {
	seedHex := generateTestSeed()
	ms := masterseed.MasterSeed{Seed: seedHex}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ms.DeriveBulk(10)
		if err != nil {
			b.Fatalf("bulk derivation 10 failed: %v", err)
		}
	}
}

// Benchmark Bulk Derivation (Large Batch - 100)
func BenchmarkDeriveBulk_100(b *testing.B) {
	seedHex := generateTestSeed()
	ms := masterseed.MasterSeed{Seed: seedHex}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ms.DeriveBulk(100)
		if err != nil {
			b.Fatalf("bulk derivation 100 failed: %v", err)
		}
	}
}

// Benchmark Bulk Derivation (XLarge Batch - 1000)
func BenchmarkDeriveBulk_1000(b *testing.B) {
	seedHex := generateTestSeed()
	ms := masterseed.MasterSeed{Seed: seedHex}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ms.DeriveBulk(1000)
		if err != nil {
			b.Fatalf("bulk derivation 1000 failed: %v", err)
		}
	}
}

// Benchmark Bulk Derivation (XXLarge Batch - 100000)
func BenchmarkDeriveBulk_100000(b *testing.B) {
	seedHex := generateTestSeed()
	ms := masterseed.MasterSeed{Seed: seedHex}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ms.DeriveBulk(100000)
		if err != nil {
			b.Fatalf("bulk derivation 100000 failed: %v", err)
		}
	}
}

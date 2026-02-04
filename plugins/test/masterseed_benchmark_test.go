package e2e

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

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

// Benchmark deriving a single output (TRNGSize bytes) from a seed block at offset 0.
// Exercises: hex decode + ChaCha expansion + hex encode.
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

// Benchmark deriving a single output using explicit offset-based stream positioning.
// Exercises: hex decode + fast skip (counter jump) + ChaCha expansion + hex encode.
func BenchmarkDeriveSingle_AtOffset(b *testing.B) {
	seedHex := generateTestSeed(b)
	ms := masterseed.MasterSeed{Seed: seedHex}

	// Pick a non-zero offset to force DiscardBytesFast() to do counter jumps.
	// 96 is 1.5 blocks (64*1 + 32), arbitrary but stable.
	const offsetBytes uint64 = 96

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ms.DeriveBulkAtOffset(1, offsetBytes)
		if err != nil {
			b.Fatalf("derivation failed: %v", err)
		}
	}
}

// Benchmark deriving a single output while simulating production cursor behavior:
// each iteration advances the offset by exactly the bytes served.
func BenchmarkDeriveSingle_CursorStyle(b *testing.B) {
	seedHex := generateTestSeed(b)
	ms := masterseed.MasterSeed{Seed: seedHex}

	outLen := masterseed.TRNGSize
	if outLen <= 0 || outLen > 1024 {
		outLen = 32
	}
	step := uint64(outLen) // count=1

	var off uint64

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ms.DeriveBulkAtOffset(1, off)
		if err != nil {
			b.Fatalf("derivation failed: %v", err)
		}
		off += step
	}
}

// Benchmark Bulk Derivation (Small Batch - 10) at offset 0.
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

// Benchmark Bulk Derivation (Small Batch - 10) using offset-based stream positioning.
func BenchmarkDeriveBulkAtOffset_10(b *testing.B) {
	seedHex := generateTestSeed(b)
	ms := masterseed.MasterSeed{Seed: seedHex}

	const offsetBytes uint64 = 96

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ms.DeriveBulkAtOffset(10, offsetBytes)
		if err != nil {
			b.Fatalf("bulk derivation at offset 10 failed: %v", err)
		}
	}
}

// Benchmark Bulk Derivation (Small Batch - 10) simulating production cursor behavior.
func BenchmarkDeriveBulk_CursorStyle_10(b *testing.B) {
	seedHex := generateTestSeed(b)
	ms := masterseed.MasterSeed{Seed: seedHex}

	outLen := masterseed.TRNGSize
	if outLen <= 0 || outLen > 1024 {
		outLen = 32
	}
	step := uint64(10 * outLen)

	var off uint64

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ms.DeriveBulkAtOffset(10, off)
		if err != nil {
			b.Fatalf("bulk derivation cursor-style 10 failed: %v", err)
		}
		off += step
	}
}

// Benchmark Bulk Derivation (Large Batch - 100) at offset 0.
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

func BenchmarkDeriveBulkAtOffset_100(b *testing.B) {
	seedHex := generateTestSeed(b)
	ms := masterseed.MasterSeed{Seed: seedHex}

	const offsetBytes uint64 = 96

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ms.DeriveBulkAtOffset(100, offsetBytes)
		if err != nil {
			b.Fatalf("bulk derivation at offset 100 failed: %v", err)
		}
	}
}

func BenchmarkDeriveBulk_CursorStyle_100(b *testing.B) {
	seedHex := generateTestSeed(b)
	ms := masterseed.MasterSeed{Seed: seedHex}

	outLen := masterseed.TRNGSize
	if outLen <= 0 || outLen > 1024 {
		outLen = 32
	}
	step := uint64(100 * outLen)

	var off uint64

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ms.DeriveBulkAtOffset(100, off)
		if err != nil {
			b.Fatalf("bulk derivation cursor-style 100 failed: %v", err)
		}
		off += step
	}
}

// Benchmark Bulk Derivation (XLarge Batch - 1000) at offset 0.
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

func BenchmarkDeriveBulkAtOffset_1000(b *testing.B) {
	seedHex := generateTestSeed(b)
	ms := masterseed.MasterSeed{Seed: seedHex}

	const offsetBytes uint64 = 96

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ms.DeriveBulkAtOffset(1000, offsetBytes)
		if err != nil {
			b.Fatalf("bulk derivation at offset 1000 failed: %v", err)
		}
	}
}

func BenchmarkDeriveBulk_CursorStyle_1000(b *testing.B) {
	seedHex := generateTestSeed(b)
	ms := masterseed.MasterSeed{Seed: seedHex}

	outLen := masterseed.TRNGSize
	if outLen <= 0 || outLen > 1024 {
		outLen = 32
	}
	step := uint64(1000 * outLen)

	var off uint64

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ms.DeriveBulkAtOffset(1000, off)
		if err != nil {
			b.Fatalf("bulk derivation cursor-style 1000 failed: %v", err)
		}
		off += step
	}
}

// Benchmark Bulk Derivation (XXLarge Batch - 100000)
// Consider running it manually with:
//
//	go test -run=^$ -bench=BenchmarkDeriveBulk_100000 -benchtime=1x ./...
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

func BenchmarkDeriveBulkAtOffset_100000(b *testing.B) {
	seedHex := generateTestSeed(b)
	ms := masterseed.MasterSeed{Seed: seedHex}

	// For huge batches, offset doesn't matter much, but it's kept non-zero
	// to ensure DiscardBytesFast is exercised.
	const offsetBytes uint64 = 96

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ms.DeriveBulkAtOffset(100000, offsetBytes)
		if err != nil {
			b.Fatalf("bulk derivation at offset 100000 failed: %v", err)
		}
	}
}

func BenchmarkDeriveBulk_CursorStyle_100000(b *testing.B) {
	seedHex := generateTestSeed(b)
	ms := masterseed.MasterSeed{Seed: seedHex}

	outLen := masterseed.TRNGSize
	if outLen <= 0 || outLen > 1024 {
		outLen = 32
	}
	step := uint64(100000 * outLen)

	var off uint64

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ms.DeriveBulkAtOffset(100000, off)
		if err != nil {
			b.Fatalf("bulk derivation cursor-style 100000 failed: %v", err)
		}
		off += step
	}
}

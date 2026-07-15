package masterseed

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// generateTestSeed returns a valid 32-byte hex seed for testing.
func generateTestSeed(t *testing.T) string {
	t.Helper()

	b := make([]byte, 32)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

// fixedSeed32Hex returns a stable, deterministic 32-byte seed block (hex-encoded).
func fixedSeed32Hex() string {
	b := make([]byte, 32)
	for i := 0; i < 32; i++ {
		b[i] = byte(i)
	}
	return hex.EncodeToString(b)
}

func TestMasterSeed_ParseTRNGBlock(t *testing.T) {
	t.Run("valid 32-byte hex parses", func(t *testing.T) {
		m := MasterSeed{Seed: fixedSeed32Hex()}
		block, err := m.parseTRNGBlock()
		require.NoError(t, err)
		require.Equal(t, byte(0x00), block[0])
		require.Equal(t, byte(0x1f), block[31])
	})

	t.Run("invalid hex fails", func(t *testing.T) {
		m := MasterSeed{Seed: "not-a-hex"}
		_, err := m.parseTRNGBlock()
		require.Error(t, err)
	})

	t.Run("wrong length fails", func(t *testing.T) {
		short := make([]byte, 31)
		m := MasterSeed{Seed: hex.EncodeToString(short)}
		_, err := m.parseTRNGBlock()
		require.Error(t, err)
	})
}

func TestMasterSeed_DeriveBulk(t *testing.T) {
	m := MasterSeed{Seed: fixedSeed32Hex()}

	t.Run("bulk derivation produces n values", func(t *testing.T) {
		vals, err := m.DeriveBulk(5, 32)
		require.NoError(t, err)
		require.Len(t, vals, 5)

		for _, v := range vals {
			require.Len(t, v, 64)
		}
	})

	t.Run("bulk derivation is deterministic for same seed and n", func(t *testing.T) {
		vals1, err1 := m.DeriveBulk(10, 32)
		vals2, err2 := m.DeriveBulk(10, 32)
		require.NoError(t, err1)
		require.NoError(t, err2)
		require.Equal(t, vals1, vals2)
	})

	t.Run("bulk derivation produces unique values within a batch", func(t *testing.T) {
		vals, err := m.DeriveBulk(50, 32)
		require.NoError(t, err)

		seen := map[string]struct{}{}
		for _, v := range vals {
			_, dup := seen[v]
			require.False(t, dup, "duplicate value in batch")
			seen[v] = struct{}{}
		}
	})

	t.Run("bulk derivation supports configured output size", func(t *testing.T) {
		vals, err := m.DeriveBulk(3, 16)
		require.NoError(t, err)
		require.Len(t, vals, 3)
		for _, v := range vals {
			require.Len(t, v, 32)
		}
	})
}

func TestMasterSeed_DeriveBulkAtOffset(t *testing.T) {
	m := MasterSeed{Seed: fixedSeed32Hex()}
	const outLen = 32

	t.Run("same offset yields deterministic results", func(t *testing.T) {
		const n = 10
		const off = uint64(0)

		vals1, err1 := m.DeriveBulkAtOffset(n, off, outLen)
		vals2, err2 := m.DeriveBulkAtOffset(n, off, outLen)
		require.NoError(t, err1)
		require.NoError(t, err2)
		require.Equal(t, vals1, vals2)
	})

	t.Run("different offsets change results", func(t *testing.T) {
		const n = 10

		vals0, err0 := m.DeriveBulkAtOffset(n, 0, outLen)
		require.NoError(t, err0)

		// shift by 1 byte (valid; stream is byte-addressable)
		vals1, err1 := m.DeriveBulkAtOffset(n, 1, outLen)
		require.NoError(t, err1)

		require.NotEqual(t, vals0, vals1)
	})

	t.Run("offset chaining does not repeat the first output", func(t *testing.T) {
		// Derive 5 outputs at offset 0, then derive 5 more starting immediately after.
		const n = 5
		startOff := uint64(0)

		first, err := m.DeriveBulkAtOffset(n, startOff, outLen)
		require.NoError(t, err)
		require.Len(t, first, n)

		// Advance offset by exactly the bytes served.
		needBytes := uint64(n * outLen)
		second, err := m.DeriveBulkAtOffset(n, startOff+needBytes, outLen)
		require.NoError(t, err)
		require.Len(t, second, n)

		// At minimum, the first element should differ.
		require.NotEqual(t, first[0], second[0])

		// Stronger: no overlap between the two batches (should hold).
		seen := map[string]struct{}{}
		for _, v := range first {
			seen[v] = struct{}{}
		}
		for _, v := range second {
			_, dup := seen[v]
			require.False(t, dup, "unexpected overlap between batches derived from adjacent offsets")
		}
	})
}

func TestDeriveOneAndBulkFromSeedHex(t *testing.T) {
	seedHex := fixedSeed32Hex()

	t.Run("DeriveOneFromSeedHex matches first element of DeriveBulkFromSeedHex(1)", func(t *testing.T) {
		one, err := DeriveOneFromSeedHex(seedHex)
		require.NoError(t, err)
		require.Len(t, one, 64)

		vals, err := DeriveBulkFromSeedHex(seedHex, 1)
		require.NoError(t, err)
		require.Len(t, vals, 1)
		require.Equal(t, one, vals[0])
	})

	t.Run("DeriveBulkFromSeedHex invalid hex fails", func(t *testing.T) {
		_, err := DeriveBulkFromSeedHex("not-a-hex", 2)
		require.Error(t, err)
	})

	t.Run("DeriveBulkFromSeedHex wrong length fails", func(t *testing.T) {
		short := make([]byte, 31)
		_, err := DeriveBulkFromSeedHex(hex.EncodeToString(short), 2)
		require.Error(t, err)
	})
}

func TestPluginReserveSeedOffsetUsesConfiguredLimit(t *testing.T) {
	p := &Plugin{
		trngSize:           32,
		maxMasterSeeds:     100,
		maxCountPerRequest: 2,
		masterSeeds:        []MasterSeed{{Seed: fixedSeed32Hex()}},
	}

	_, _, err := p.reserveSeedOffset(3)
	require.Error(t, err)
	require.Contains(t, err.Error(), "count too large")
}

func TestPluginAddMasterSeedUsesConfiguredCapacity(t *testing.T) {
	p := &Plugin{
		trngSize:       32,
		maxMasterSeeds: 1,
		masterSeeds:    make([]MasterSeed, 0, 1),
	}

	p.addMasterSeed(fixedSeed32Hex())
	p.addMasterSeed(generateTestSeed(t))

	require.Len(t, p.masterSeeds, 1)
}

func TestDeriveBulk_Uniqueness_100k(t *testing.T) {
	t.Skip("expensive; run manually when needed")

	const count = 100000
	seedHex := generateTestSeed(t)
	ms := MasterSeed{Seed: seedHex}

	results, err := ms.DeriveBulk(count, 32)
	require.NoError(t, err)
	require.Len(t, results, count)

	seen := make(map[string]struct{}, count)
	for i, val := range results {
		if _, ok := seen[val]; ok {
			t.Fatalf("duplicate found at index %d: %s", i, val)
		}
		seen[val] = struct{}{}
	}
}

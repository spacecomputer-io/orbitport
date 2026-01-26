package masterseed

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

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
		vals, err := m.DeriveBulk(5)
		require.NoError(t, err)
		require.Len(t, vals, 5)

		for _, v := range vals {
			require.Len(t, v, TRNGSize*2)
		}
	})

	t.Run("bulk derivation is deterministic for same seed and n", func(t *testing.T) {
		vals1, err1 := m.DeriveBulk(10)
		vals2, err2 := m.DeriveBulk(10)
		require.NoError(t, err1)
		require.NoError(t, err2)
		require.Equal(t, vals1, vals2)
	})

	t.Run("bulk derivation produces unique values within a batch", func(t *testing.T) {
		vals, err := m.DeriveBulk(50)
		require.NoError(t, err)

		seen := map[string]struct{}{}
		for _, v := range vals {
			_, dup := seen[v]
			require.False(t, dup, "duplicate value in batch")
			seen[v] = struct{}{}
		}
	})
}

func TestMasterSeed_DeriveBulkWithNonce(t *testing.T) {
	m := MasterSeed{Seed: fixedSeed32Hex()}

	t.Run("same nonce+seq yields deterministic results", func(t *testing.T) {
		nonce := int64(123456789)
		seq := uint64(42)

		vals1, err1 := m.DeriveBulkWithNonce(10, nonce, seq)
		vals2, err2 := m.DeriveBulkWithNonce(10, nonce, seq)
		require.NoError(t, err1)
		require.NoError(t, err2)
		require.Equal(t, vals1, vals2)
	})

	t.Run("different seq changes results (even with same nonce)", func(t *testing.T) {
		nonce := int64(123456789)

		vals1, err1 := m.DeriveBulkWithNonce(10, nonce, 1)
		vals2, err2 := m.DeriveBulkWithNonce(10, nonce, 2)
		require.NoError(t, err1)
		require.NoError(t, err2)
		require.NotEqual(t, vals1, vals2)
	})

	t.Run("different nonce changes results (even with same seq)", func(t *testing.T) {
		seq := uint64(99)

		vals1, err1 := m.DeriveBulkWithNonce(10, 111, seq)
		vals2, err2 := m.DeriveBulkWithNonce(10, 222, seq)
		require.NoError(t, err1)
		require.NoError(t, err2)
		require.NotEqual(t, vals1, vals2)
	})

	t.Run("nonce mode still unique within a batch", func(t *testing.T) {
		vals, err := m.DeriveBulkWithNonce(200, time.Now().UnixNano(), 7)
		require.NoError(t, err)

		seen := map[string]struct{}{}
		for _, v := range vals {
			_, dup := seen[v]
			require.False(t, dup, "duplicate value in batch")
			seen[v] = struct{}{}
		}
	})
}

func TestDeriveOneAndBulkFromSeedHex(t *testing.T) {
	seedHex := fixedSeed32Hex()

	t.Run("DeriveOneFromSeedHex matches first element of DeriveBulkFromSeedHex(1)", func(t *testing.T) {
		one, err := DeriveOneFromSeedHex(seedHex)
		require.NoError(t, err)
		require.Len(t, one, TRNGSize*2)

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

func TestDeriveBulk_Uniqueness_100k(t *testing.T) {
	t.Skip("expensive; run manually when needed")

	const count = 100000
	seedHex := generateTestSeed(t)
	ms := MasterSeed{Seed: seedHex}

	results, err := ms.DeriveBulk(count)
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

package masterseed

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// Generate a valid 32-byte hex seed for testing
func generateTestSeed() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func TestMasterSeed_Derive(t *testing.T) {
	seedHex := hex.EncodeToString([]byte("this-is-32-byte-long-seed-for-test!!"))
	m := MasterSeed{Seed: seedHex}

	t.Run("derive index 0 works", func(t *testing.T) {
		val, err := m.Derive(0)
		exp := "0592ff0ede8d90336ed45d78eabc52cb117bf3511492799512c917f50c25cfc0"
		require.NoError(t, err)
		require.Len(t, val, TRNGSize*2, "should return 64 hex chars")
		require.Equal(t, exp, val, "actual value should be expected")
	})

	t.Run("derive index is deterministic", func(t *testing.T) {
		val1, err1 := m.Derive(1)
		val2, err2 := m.Derive(1)
		require.NoError(t, err1)
		require.NoError(t, err2)
		require.Equal(t, val1, val2, "same index must yield same result")
	})

	t.Run("different indices produce different outputs", func(t *testing.T) {
		val1, _ := m.Derive(0)
		val2, _ := m.Derive(1)
		require.NotEqual(t, val1, val2, "different indices must yield different results")
	})

	t.Run("invalid hex seed fails", func(t *testing.T) {
		bad := MasterSeed{Seed: "not-a-hex"}
		_, err := bad.Derive(0)
		require.Error(t, err, "invalid hex seed should error")
	})
}

func TestMasterSeed_DeriveBulk(t *testing.T) {
	seedHex := hex.EncodeToString([]byte("this-is-32-byte-long-seed-for-test!!"))
	m := MasterSeed{Seed: seedHex}

	t.Run("bulk derivation produces n values", func(t *testing.T) {
		vals, err := m.DeriveBulk(5)
		require.NoError(t, err)
		require.Len(t, vals, 5)
	})

	t.Run("bulk derivation produces unique values", func(t *testing.T) {
		vals, _ := m.DeriveBulk(6)
		seen := map[string]struct{}{}
		for _, v := range vals {
			_, dup := seen[v]
			require.False(t, dup, "duplicate CTRNG in batch")
			seen[v] = struct{}{}
		}
	})
}

func TestDeriveBulk_Uniqueness_100k(t *testing.T) {
	count := 100000
	seedHex := generateTestSeed()
	ms := MasterSeed{Seed: seedHex}

	t.Logf("Starting generation of %d values (this may take 30 seconds)...", count)

	results, err := ms.DeriveBulk(count)
	if err != nil {
		t.Fatalf("DeriveBulk failed: %v", err)
	}

	seen := make(map[string]bool, count)
	collisions := 0

	for i, val := range results {
		if seen[val] {
			t.Errorf("Duplicate found at index %d: %s", i, val)
			collisions++
		}
		seen[val] = true
	}

	if collisions > 0 {
		t.Fatalf("FAILED: Found %d collisions in %d generated values", collisions, count)
	}

	t.Logf("SUCCESS: Generated %d values with 0 collisions.", count)
}

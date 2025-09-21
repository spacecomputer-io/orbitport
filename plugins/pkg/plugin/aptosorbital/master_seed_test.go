package aptosorbital

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

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

	t.Run("bulk derivation is consistent with single derivation", func(t *testing.T) {
		vals, _ := m.DeriveBulk(3)
		for i := 0; i < 3; i++ {
			indVal, _ := m.Derive(uint32(i))
			require.Equal(t, indVal, vals[i], "bulk derivation must match individual Derive")
		}
	})

	t.Run("bulk derivation produces unique values", func(t *testing.T) {
		vals, _ := m.DeriveBulk(4)
		for i := 0; i < 4; i++ {
			for j := i + 1; j < 4; j++ {
				require.NotEqual(t, vals[i], vals[j], "bluk derivation values of different indices must be unique")
			}
		}
	})
}

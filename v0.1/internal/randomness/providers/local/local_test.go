package localrand

import (
	"testing"

	randomness_common "github.com/spacecomputerio/orbitport/internal/randomness/common"
	"github.com/stretchr/testify/require"
)

func TestLocalGoCrypto(t *testing.T) {
	seed, err := GenerateLocalRandomSeed(32)
	require.NoError(t, err)
	require.Len(t, seed.Value, 32)
	require.Equal(t, "", seed.Sig)
	require.Equal(t, randomness_common.RandSourceLocalGoCrypto, seed.Src)
}

func TestGenerateSpaceDerviedSeed(t *testing.T) {
	// masterSeedVal := "56f9b7332e4c704ae4d059e1c91a2ba6fdac2eaf8a8c02c917738f7a5eca6813"
	maxUse := 100
	restore := setMaxDervied(uint32(maxUse))
	defer restore()

	masterSeedVal := "2499a024769ced739ccf614cae195540246ad2edb2290ec9955fb687016e4c1f"
	masterSeed, err := NewMasterSeed([]byte(masterSeedVal))
	require.NoError(t, err)
	values := map[string]bool{}

	for i := 0; i < maxUse; i++ {
		seed, err := masterSeed.Next(64)
		require.NoError(t, err)
		require.Len(t, seed.Value, 64)
		require.Equal(t, "", seed.Sig)
		require.Equal(t, randomness_common.RandSourceLocalDrivedFromSpaceSeed, seed.Src)
		values[seed.Value] = true
	}
	// call after maxUse to fail
	s, err := masterSeed.Next(64)
	require.Error(t, err)
	require.Equal(t, ErrMasterSeedExhausted, err)
	require.Nil(t, s)
	// ensure that the same seed is not returned twice
	require.Equal(t, maxUse, len(values))
}

func setMaxDervied(val uint32) func() {
	orig := MaxDervied
	MaxDervied = val
	return func() {
		MaxDervied = orig
	}
}

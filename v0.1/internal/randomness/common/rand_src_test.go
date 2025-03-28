package randomness_common

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRandomSeedStruct(t *testing.T) {
	var rs RandomSeed
	rs.Value = "value"
	rs.Sig = "sig"
	rs.Src = RandSourceAptosOrbital

	b, err := json.Marshal(rs)
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf(`{"value":"value","sig":"sig","src":"%s"}`, RandSourceAptosOrbital.String()), string(b))

	var rs2 RandomSeed
	err = json.Unmarshal(b, &rs2)
	require.NoError(t, err)

	require.Equal(t, RandSourceAptosOrbital, rs2.Src)
	require.Equal(t, "value", rs2.Value)
	require.Equal(t, "sig", rs2.Sig)
}

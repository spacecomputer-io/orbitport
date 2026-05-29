package masterseed

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type goldenVector struct {
	Name         string   `json:"name"`
	Mode         string   `json:"mode"`
	TrngBlockHex string   `json:"trng_block_hex"`
	SeedHex      string   `json:"seed_hex"`
	OffsetBytes  uint64   `json:"offset_bytes"`
	TrngSize     int      `json:"trng_size"`
	Count        int      `json:"count"`
	OutputsHex   []string `json:"outputs_hex"`
}

func loadGoldenVectors(t *testing.T) []goldenVector {
	t.Helper()

	candidates := []string{
		filepath.Join("testdata", "golden_vectors.json"),
		"golden_vectors.json",
	}

	var (
		data []byte
		err  error
		used string
	)

	for _, p := range candidates {
		data, err = os.ReadFile(p)
		if err == nil {
			used = p
			break
		}
	}
	require.NoError(t, err, "failed to read golden_vectors.json from any candidate path: %v", candidates)
	t.Logf("Loaded golden vectors from %s", used)

	var vecs []goldenVector
	require.NoError(t, json.Unmarshal(data, &vecs))
	require.NotEmpty(t, vecs)

	return vecs
}

func findVectorByPrefix(t *testing.T, vecs []goldenVector, prefix string) goldenVector {
	t.Helper()

	for _, v := range vecs {
		if strings.HasPrefix(v.Name, prefix) {
			return v
		}
	}
	t.Fatalf("golden vector with prefix %q not found", prefix)
	return goldenVector{}
}

func TestGoldenVector_D_DirectBlockSeed_Offset0(t *testing.T) {
	vecs := loadGoldenVectors(t)
	v := findVectorByPrefix(t, vecs, "D_")

	require.Equal(t, 32, v.TrngSize, "this test assumes 32-byte outputs")
	require.Equal(t, uint64(0), v.OffsetBytes, "vector D should be offset 0")
	require.Greater(t, v.Count, 0)
	require.Len(t, v.OutputsHex, v.Count)

	ms := MasterSeed{Seed: v.TrngBlockHex}
	got, err := ms.DeriveBulkAtOffset(v.Count, v.OffsetBytes, v.TrngSize)
	require.NoError(t, err)

	require.Equal(t, v.OutputsHex, got, "vector %q mismatch (mode=%q, offset=%d)", v.Name, v.Mode, v.OffsetBytes)
}

func TestGoldenVector_E_OffsetBasedStream(t *testing.T) {
	vecs := loadGoldenVectors(t)
	v := findVectorByPrefix(t, vecs, "E_")

	require.Equal(t, 32, v.TrngSize, "this test assumes 32-byte outputs")
	require.Greater(t, v.OffsetBytes, uint64(0), "vector E should have a non-zero offset")
	require.Greater(t, v.Count, 0)
	require.Len(t, v.OutputsHex, v.Count)

	ms := MasterSeed{Seed: v.TrngBlockHex}
	got, err := ms.DeriveBulkAtOffset(v.Count, v.OffsetBytes, v.TrngSize)
	require.NoError(t, err)

	require.Equal(t, v.OutputsHex, got, "vector %q mismatch (mode=%q, offset=%d)", v.Name, v.Mode, v.OffsetBytes)
}

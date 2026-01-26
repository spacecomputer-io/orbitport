package masterseed

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type goldenVector struct {
	Name           string   `json:"name"`
	Mode           string   `json:"mode"`
	ExecutionIDHex *string  `json:"execution_id_hex"`
	PartyID        *uint16  `json:"party_id"`
	Counter        *uint64  `json:"counter"`
	TrngBlockHex   string   `json:"trng_block_hex"`
	SeedHex        string   `json:"seed_hex"`
	TrngSize       int      `json:"trng_size"`
	Count          int      `json:"count"`
	OutputsHex     []string `json:"outputs_hex"`
}

func loadGoldenVectors(t *testing.T) []goldenVector {
	t.Helper()

	candidates := []string{
		filepath.Join("testdata", "golden_vectors.json"),
		"golden_vectors.json",
	}

	var data []byte
	var err error
	var used string

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
		if len(v.Name) >= len(prefix) && v.Name[:len(prefix)] == prefix {
			return v
		}
	}
	t.Fatalf("golden vector with prefix %q not found", prefix)
	return goldenVector{}
}

func TestGoldenVector_D_DirectBlockSeed(t *testing.T) {
	vecs := loadGoldenVectors(t)
	v := findVectorByPrefix(t, vecs, "D_")

	require.Equal(t, 32, v.TrngSize, "this test assumes 32-byte outputs")
	require.Greater(t, v.Count, 0)
	require.Len(t, v.OutputsHex, v.Count)

	// Ensure runtime config matches the vector expectations.
	TRNGSize = v.TrngSize

	got, err := DeriveBulkFromSeedHex(v.TrngBlockHex, v.Count)
	require.NoError(t, err)
	require.Equal(t, v.OutputsHex, got, "vector %q mismatch (mode=%q)", v.Name, v.Mode)
}

func TestGoldenVector_E_BlockNonceSeqSha256(t *testing.T) {
	vecs := loadGoldenVectors(t)
	v := findVectorByPrefix(t, vecs, "E_")

	require.Equal(t, 32, v.TrngSize, "this test assumes 32-byte outputs")
	require.Greater(t, v.Count, 0)
	require.Len(t, v.OutputsHex, v.Count)

	// Ensure runtime config matches the vector expectations.
	TRNGSize = v.TrngSize

	// These MUST match the constants in your Rust generator.
	const nonceNanos int64 = 1700000000000000000
	const seq uint64 = 7

	ms := MasterSeed{Seed: v.TrngBlockHex}
	got, err := ms.DeriveBulkWithNonce(v.Count, nonceNanos, seq)
	require.NoError(t, err)

	require.Equal(t, v.OutputsHex, got, "vector %q mismatch (mode=%q)", v.Name, v.Mode)
}

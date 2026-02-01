package masterseed

import (
	"encoding/hex"
	"fmt"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/chacha20"
)

var (
	TRNGSize           = 32  // default
	MaxMasterSeeds     = 100 // default
	MaserSeedPeriod    = int64(3600)
	MaxCountPerRequest = 25000
)

type MasterSeed struct {
	Seed   string // hex-encoded 32-byte cTRNG block
	Offset uint64 // current byte offset in the ChaCha keystream
}

func LoadMasterSeedConfig(cfg *masterSeedConfig) {
	TRNGSize = cfg.MasterSeedTRNGSize
	MaxMasterSeeds = cfg.MasterSeedMaxMasterSeeds
	MaserSeedPeriod = cfg.MaserSeedPeriod
	if cfg.MasterSeedMaxCountPerRequest > 0 && cfg.MasterSeedMaxCountPerRequest <= MaxCountPerRequest {
		MaxCountPerRequest = cfg.MasterSeedMaxCountPerRequest
	}
}

// parseTRNGBlock decodes the master seed hex string into a fixed [32]byte block.
// This block is used directly as ChaCha20Rng::from_seed(seed_block), matching Rust.
func (m MasterSeed) parseTRNGBlock() ([32]byte, error) {
	var block [32]byte

	raw, err := hex.DecodeString(m.Seed)
	if err != nil {
		return block, fmt.Errorf("failed to decode master seed hex: %w", err)
	}
	if len(raw) != 32 {
		return block, fmt.Errorf("master seed length is %d bytes (hex len %d), expected 32 bytes (hex len 64)",
			len(raw), len(m.Seed))
	}

	copy(block[:], raw)
	return block, nil
}

// DeriveBulkAtOffset derives n outputs from this seed, starting at a specific byte offset
// in the ChaCha keystream (offset=0 means the very beginning).
// This is the primitive used with a per-seed cursor: plugin decides the offset, from which bytes are producted.
func (m MasterSeed) DeriveBulkAtOffset(n int, offsetBytes uint64) ([]string, error) {
	if n <= 0 {
		return []string{}, nil
	}

	outLen := TRNGSize
	if outLen <= 0 || outLen > 1024 {
		outLen = 32
	}

	if n > MaxCountPerRequest {
		return nil, fmt.Errorf("n too large: %d (max %d)", n, MaxCountPerRequest)
	}

	need, ok := mulUint64Checked(uint64(n), uint64(outLen))
	if !ok {
		return nil, fmt.Errorf("byte requirement overflow: n=%d outLen=%d", n, outLen)
	}

	// make([]byte, int(need)) must fit into int on this architecture
	maxInt := int(^uint(0) >> 1)
	if need > uint64(maxInt) {
		return nil, fmt.Errorf("request too large: need=%d bytes exceeds max int=%d", need, maxInt)
	}

	seedBlock, err := m.parseTRNGBlock()
	if err != nil {
		return nil, err
	}

	rng := chacha20.New(seedBlock)
	rng.DiscardBytesFast(offsetBytes)

	buf := make([]byte, int(need))
	rng.FillBytes(buf)

	results := make([]string, 0, n)
	for i := 0; i < n; i++ {
		start := i * outLen
		end := start + outLen
		results = append(results, hex.EncodeToString(buf[start:end]))
	}
	return results, nil
}

// DeriveBulk keeps the original deterministic behavior starting from offset 0.
// Useful for tests and for matching Rust exactly when uniqueness/cursor behavior is not required.
func (m MasterSeed) DeriveBulk(n int) ([]string, error) {
	return m.DeriveBulkAtOffset(n, 0)
}

// DeriveOneFromSeedHex derives one output value from a hex-encoded 32-byte seed block.
func DeriveOneFromSeedHex(seedHex string) (string, error) {
	ms := MasterSeed{Seed: seedHex}
	vals, err := ms.DeriveBulk(1)
	if err != nil {
		return "", err
	}
	if len(vals) == 0 {
		return "", fmt.Errorf("no value produced")
	}
	return vals[0], nil
}

// DeriveBulkFromSeedHex derives n output values from a hex-encoded 32-byte seed block.
func DeriveBulkFromSeedHex(seedHex string, n int) ([]string, error) {
	ms := MasterSeed{Seed: seedHex}
	return ms.DeriveBulk(n)
}

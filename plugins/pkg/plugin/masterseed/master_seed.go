package masterseed

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

var (
	TRNGSize        = 32  // default
	MaxMasterSeeds  = 100 // default
	MaserSeedPeriod = int64(3600)
)

type MasterSeed struct {
	Seed string // hex-encoded 32-byte cTRNG block
}

func LoadMasterSeedConfig(cfg *masterSeedConfig) {
	TRNGSize = cfg.MasterSeedTRNGSize
	MaxMasterSeeds = cfg.MasterSeedMaxMasterSeeds
	MaserSeedPeriod = cfg.MaserSeedPeriod
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

// DeriveBulk derives n deterministic outputs from a single 32-byte cTRNG block,
// by treating the block as the ChaCha20Rng seed (no extra hashing/context).
//
// This is the direct Go equivalent of:
//
//	rng = ChaCha20Rng::from_seed(seed_block)
//	rng.fill_bytes(&mut output)
//
// and it is the mode that should match Rust rand_chacha outputs exactly.
func (m MasterSeed) DeriveBulk(n int) ([]string, error) {
	if n <= 0 {
		return []string{}, nil
	}

	seedBlock, err := m.parseTRNGBlock()
	if err != nil {
		return nil, err
	}

	rng := FromSeed(seedBlock)

	outLen := TRNGSize
	if outLen <= 0 || outLen > 1024 {
		outLen = 32
	}

	buf := make([]byte, n*outLen)
	rng.FillBytes(buf)

	results := make([]string, 0, n)
	for i := 0; i < n; i++ {
		start := i * outLen
		end := start + outLen
		results = append(results, hex.EncodeToString(buf[start:end]))
	}
	return results, nil
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

// DeriveBulkWithNonce derives n outputs like DeriveBulk, but makes them unique per call
// by deriving the ChaCha seed from (seedBlock + nonce + seq).
// This guarantees that even if the same 32-byte cTRNG block is used repeatedly/concurrently,
// outputs will differ as long as (nonceNanos, seq) is unique.
func (m MasterSeed) DeriveBulkWithNonce(n int, nonceNanos int64, seq uint64) ([]string, error) {
	if n <= 0 {
		return []string{}, nil
	}

	seedBlock, err := m.parseTRNGBlock()
	if err != nil {
		return nil, err
	}

	derivedSeed := deriveSeedFromBlockAndNonce(seedBlock, nonceNanos, seq)

	rng := FromSeed(derivedSeed)

	outLen := TRNGSize
	if outLen <= 0 || outLen > 1024 {
		outLen = 32
	}

	buf := make([]byte, n*outLen)
	rng.FillBytes(buf)

	results := make([]string, 0, n)
	for i := 0; i < n; i++ {
		start := i * outLen
		end := start + outLen
		results = append(results, hex.EncodeToString(buf[start:end]))
	}
	return results, nil
}

// deriveSeedFromBlockAndNonce produces a 32-byte ChaCha seed from:
// SHA256(seedBlock || BE(nonceNanos) || BE(seq))
func deriveSeedFromBlockAndNonce(seedBlock [32]byte, nonceNanos int64, seq uint64) [32]byte {
	h := sha256.New()
	h.Write(seedBlock[:])

	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], uint64(nonceNanos))
	h.Write(nb[:])

	var sb [8]byte
	binary.BigEndian.PutUint64(sb[:], seq)
	h.Write(sb[:])

	sum := h.Sum(nil)

	var out [32]byte
	copy(out[:], sum[:32])
	return out
}

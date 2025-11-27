package masterseed

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
)

var (
	TRNGSize        = 32 // default
	MaxMasterSeeds  = 10 // default
	MaserSeedPeriod = int64(3600)
	chainParams     = &chaincfg.MainNetParams
)

// BIP-32 subindex range limit (M = 2^31-1), a Mersenne prime
// randIndex samples uniformly from [0, indexMod) using crypto/rand with rejection sampling.
const indexMod uint64 = (1 << 31) - 1

type MasterSeed struct {
	Seed string // hex used for BIP32
}

func randIndex() (uint32, error) {
	// Rejection sampling to avoid modulo bias.
	const maxUint64 = ^uint64(0)
	limit := maxUint64 - (maxUint64 % indexMod)

	for {
		var buf [8]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, fmt.Errorf("crypto/rand failed: %w", err)
		}
		r := binary.LittleEndian.Uint64(buf[:])

		// Only accept values in [0, limit). makes r % indexMod uniform.
		if r < limit {
			return uint32(r % indexMod), nil
		}
	}
}

func mixWithNonceHex(hexVal string, nonce int64) (string, error) {
	raw, err := hex.DecodeString(hexVal)
	if err != nil {
		return "", fmt.Errorf("bad hex to mix: %w", err)
	}
	var nb [8]byte
	binary.LittleEndian.PutUint64(nb[:], uint64(nonce))

	h := sha256.New()
	_, _ = h.Write(raw)
	_, _ = h.Write(nb[:])
	sum := h.Sum(nil)

	// avoid mutating the global TRNGSize
	outLen := TRNGSize
	if outLen < 1 || outLen > len(sum) {
		outLen = len(sum) // 32
	}
	return hex.EncodeToString(sum[:outLen]), nil
}

func LoadMasterSeedConfig(cfg *masterSeedConfig) {
	TRNGSize = cfg.MasterSeedTRNGSize
	MaxMasterSeeds = cfg.MasterSeedMaxMasterSeeds
	MaserSeedPeriod = cfg.MaserSeedPeriod
}

// derive single deterministic rng from master seed
func (m MasterSeed) Derive(index uint32) (string, error) {
	seedBytes, err := hex.DecodeString(m.Seed)
	if err != nil {
		return "", fmt.Errorf("failed to decode master seed: %w", err)
	}

	rootKey, err := hdkeychain.NewMaster(seedBytes, chainParams)
	if err != nil {
		return "", fmt.Errorf("failed to create root key: %w", err)
	}

	childKey, err := rootKey.Child(hdkeychain.HardenedKeyStart + index)
	if err != nil {
		return "", fmt.Errorf("failed to derive child key: %w", err)
	}

	// public key bytes serve as deterministic randomess
	pubKey, err := childKey.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("failed to get pubkey: %w", err)
	}

	// 33-byte compressed format
	pubBytes := pubKey.SerializeCompressed()

	hash := sha256.Sum256(pubBytes)
	rndBytes := hash[:TRNGSize]

	return hex.EncodeToString(rndBytes), nil
}

// derive multiple (n) deterministic rngs from master seed (produces n values by deriving indices randomly)
// block nonce is mixed in to prevent repeats across multiple calls
func (m MasterSeed) DeriveBulk(n int) ([]string, error) {
	if n <= 0 || uint64(n) >= indexMod {
		return []string{}, nil
	}

	blockNonce := time.Now().UnixNano()
	results := make([]string, 0, n)

	for len(results) < n {
		idx, err := randIndex()
		if err != nil {
			return nil, fmt.Errorf("failed to get random index: %w", err)
		}

		baseHex, err := m.Derive(idx) // existing BIP32-based derivation
		if err != nil {
			return nil, fmt.Errorf("failed to derive index %d: %w", idx, err)
		}

		// ensure uniqueness within batch
		nonce := blockNonce + int64(len(results))

		// mix in the value-level nonce so that values are unique even if baseHex collides
		mixedHex, err := mixWithNonceHex(baseHex, nonce)
		if err != nil {
			return nil, err
		}

		results = append(results, mixedHex)
	}
	return results, nil
}

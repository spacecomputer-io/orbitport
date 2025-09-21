package aptosorbital

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
)

var (
	TRNGSize       = 32 // default
	MaxMasterSeeds = 10 // default

	chainParams = &chaincfg.MainNetParams
)

type MasterSeed struct {
	Seed string // hex used for BIP32
}

func LoadMasterSeedConfig(cfg *aptosOrbitalConfig) {
	TRNGSize = cfg.AptosOrbitalTRNGSize
	MaxMasterSeeds = cfg.AptosOrbitalMaxMasterSeeds
}

// derive single deterministic rng from master seed
func (m MasterSeed) Derive(index uint32) (string, error) {
	seedBytes, err := hex.DecodeString(m.Seed)
	if err != nil {
		return "", fmt.Errorf("failed to decode master seed: %w", err)
	}

	// chainParams := chaincfg.Params{}
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

// derive multiple (n) deterministic rngs from master seed (produces n values by deriving indices 0..n-1)
func (m MasterSeed) DeriveBulk(n int) ([]string, error) {
	results := make([]string, 0, n)
	for i := 0; i < n; i++ {
		val, err := m.Derive(uint32(i))
		if err != nil {
			return nil, fmt.Errorf("failed to derive index %d: %v", i, err)
		}
		results = append(results, val)
	}
	return results, nil
}

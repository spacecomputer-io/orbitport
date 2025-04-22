package localrand

import (
	"encoding/hex"
	"fmt"
	"sync/atomic"

	randomness_common "github.com/spacecomputerio/orbitport/internal/randomness/common"
	"github.com/tyler-smith/go-bip32"
)

var (
	// ErrMasterSeedExhausted is returned when the master seed has reached its maximum use
	ErrMasterSeedExhausted = fmt.Errorf("master seed has reached its maximum use")
	// MaxDervied is the maximum number of times a master seed can be used
	MaxDervied uint32 = 1000
	// prefix to trim from the derived key
	keyPrefixSize = 25
)

// / NewMasterSeed creates a new master seed that can be used to derive new random seeds.
func NewMasterSeed(seed []byte) (*MasterSeed, error) {
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, err
	}
	return &MasterSeed{
		masterKey: masterKey,
	}, nil
}

// / MasterSeed is used to derive new random seeds.
// / It holds a master key that is used to derive new keys where we use their bytes as random numbers.
// / The master key is based on the given seed, and can be used to derive a maximum of 1000 keys.
type MasterSeed struct {
	masterKey *bip32.Key
	index     atomic.Uint32
}

// / Next returns the next derived seed or an error if the maximum number of uses has been reached.
func (m *MasterSeed) Next(n int) (*randomness_common.RandomSeed, error) {
	i := m.index.Add(1)
	if i > MaxDervied {
		return nil, ErrMasterSeedExhausted
	}
	derivedKey, err := m.masterKey.NewChildKey(i)
	if err != nil {
		return nil, fmt.Errorf("failed to derive child key: %w", err)
	}

	keyBytes, err := derivedKey.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize derived key: %w", err)
	}
	rseed := hex.EncodeToString(keyBytes)
	if len(rseed) < n+keyPrefixSize {
		return nil, fmt.Errorf("derived key is too short: %d", len(rseed))
	}
	return &randomness_common.RandomSeed{
		Value: rseed[keyPrefixSize : n+keyPrefixSize],
		Sig:   "",
		Src:   randomness_common.RandSourceLocalDrivedFromSpaceSeed,
	}, nil
}

func (m *MasterSeed) Index() uint32 {
	return m.index.Load()
}

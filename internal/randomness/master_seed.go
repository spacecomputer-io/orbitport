package randomness

import (
	"sync"

	randomness_common "github.com/spacecoinxyz/orbitport/internal/randomness/common"
	"github.com/spacecoinxyz/orbitport/internal/randomness/providers"
)

type masterSeed struct {
	mu   sync.RWMutex
	Seed *randomness_common.RandomSeed
}

func NewMasterSeed() *masterSeed {
	return &masterSeed{}
}

func (ms *masterSeed) GetSeed() *randomness_common.RandomSeed {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	return ms.Seed
}

func (ms *masterSeed) SetSeed(seed *randomness_common.RandomSeed) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if seed != nil {
		// update the source of the seed
		seed.Src = providers.RandSourceLocalDrivedFromSpaceSeed
	}
	ms.Seed = seed
}

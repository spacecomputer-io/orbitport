package randomness

import (
	randomness_common "github.com/spacecoinxyz/stargate/internal/randomness/common"
	"github.com/spacecoinxyz/stargate/internal/randomness/providers/aptosorbital"
)

// randomnessService implements the randomness service.
type randomnessService struct {
	aptosClient *aptosorbital.AptosClient
}

// NewService creates a new randomness service.
func NewService(aptosClient *aptosorbital.AptosClient) randomness_common.Service {
	return &randomnessService{
		aptosClient: aptosClient,
	}
}

// GetRandomSeed retrieves a true randomness seed from the Aptos Orbital API.
func (s *randomnessService) GetRandomSeed() (randomness_common.RandomSeed, error) {
	seed, err := s.aptosClient.GetTrueRandomnessSeed(0, 1)
	if err != nil {
		return nil, err
	}
	return seed, nil
}

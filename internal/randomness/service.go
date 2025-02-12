package randomness

import (
	"context"
	"fmt"

	"github.com/spacecoinxyz/orbitport/internal/config"
	randomness_common "github.com/spacecoinxyz/orbitport/internal/randomness/common"
	"github.com/spacecoinxyz/orbitport/internal/randomness/providers/aptosorbital"
	provider_local "github.com/spacecoinxyz/orbitport/internal/randomness/providers/local"
)

// randomnessService implements the randomness service.
type randomnessService struct {
	aptosClient *aptosorbital.AptosClient
}

// NewService creates a new randomness service.
func NewWithClient(aptosClient *aptosorbital.AptosClient) randomness_common.Service {
	return &randomnessService{
		aptosClient: aptosClient,
	}
}

func New(cfg config.Config) (randomness_common.Service, error) {
	aptosClient, err := aptosorbital.NewClient(
		aptosorbital.WithApiURL(cfg.AptosOrbitalApiUrl),
		aptosorbital.WithAuthURL(cfg.AptosOrbitalAuthUrl),
		aptosorbital.WithClientID(cfg.AptosOrbitalClientId),
		aptosorbital.WithClientSecret(cfg.AptosOrbitalClientSecret),
		aptosorbital.WithRateLimit(float64(cfg.AptosOrbitalRateLimit), 2),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Aptos Orbital client: %w", err)
	}
	return NewWithClient(aptosClient), nil
}

// GetRandomSeed retrieves a true randomness seed from the Aptos Orbital API.
func (s *randomnessService) GetRandomSeed(ctx context.Context) (*randomness_common.RandomSeed, error) {
	seed, err := s.aptosClient.GetTrueRandomnessSeed(ctx, false, 1)
	if err != nil {
		// if limit exceeded, generate random seed locally
		// TODO: think about this some more, will be changed once the aggregation is implemented
		if err == aptosorbital.ErrRateLimitExceeded {
			localSeed, errLocal := provider_local.GenerateRandomSeed(32)
			if errLocal != nil {
				return nil, err
			}
			return localSeed, nil
		}
		return nil, err
	}
	return seed, nil
}

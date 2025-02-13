package randomness

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spacecoinxyz/orbitport/internal/config"
	randomness_common "github.com/spacecoinxyz/orbitport/internal/randomness/common"
	"github.com/spacecoinxyz/orbitport/internal/randomness/providers"
	"github.com/spacecoinxyz/orbitport/internal/randomness/providers/aptosorbital"
	go_crypto "github.com/spacecoinxyz/orbitport/internal/randomness/providers/local/go-crypto"
	"github.com/spacecoinxyz/orbitport/internal/utils"
)

var (
	ErrNoMasterSeedSet = errors.New("no master seed set")
)

// randomnessService implements the randomness service.
type randomnessService struct {
	threadControl utils.ThreadControl
	logger        *utils.Logger

	aptosClient *aptosorbital.AptosClient

	masterSeed         *utils.Locked[*randomness_common.RandomSeed]
	masterSeedInterval time.Duration
}

// NewService creates a new randomness service.
func NewWithClient(aptosClient *aptosorbital.AptosClient, masterSeedInterval time.Duration) randomness_common.Service {
	service := &randomnessService{
		logger:             utils.GetLogger("orbitport:rand:service"),
		aptosClient:        aptosClient,
		threadControl:      utils.NewThreadControl(),
		masterSeed:         utils.NewLocked[*randomness_common.RandomSeed](nil),
		masterSeedInterval: masterSeedInterval,
	}

	return service
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
	return NewWithClient(aptosClient, cfg.MasterSeedInterval), nil
}

// Start starts the randomness service background routines:
// 1. update the master seed every masterSeedInterval
func (s *randomnessService) Start(ctx context.Context) error {
	ticker := time.NewTicker(s.masterSeedInterval)

	s.threadControl.GoCtx(ctx, func(ctx context.Context) {
		for {
			select {
			case <-ticker.C:
				seed, err := s.GetRandomSeed(ctx)
				if err != nil {
					return
				}
				if seed != nil {
					// update the source of the seed
					seed.Src = providers.RandSourceLocalDrivedFromSpaceSeed
				}
				s.masterSeed.Set(seed)
			case <-ctx.Done():
				return
			}
		}
	})

	return nil
}

// Close closes the randomness service and all running goroutines.
func (s *randomnessService) Close() {
	s.threadControl.Close()
}

// GetRandomSeed retrieves a true randomness seed from the Aptos Orbital API.
// sources is a prioritized list of randomness sources to try.
func (s *randomnessService) GetRandomSeed(ctx context.Context, sources ...providers.RandSource) (*randomness_common.RandomSeed, error) {
	if len(sources) == 0 {
		sources = providers.DefaultSources
	}

	s.logger.Debug("getting randomness seed", "sources", sources)

	var seed *randomness_common.RandomSeed
	var err error
	for _, src := range sources {
		switch src {
		case providers.RandSourceAptosOrbital:
			seed, err = s.aptosClient.GetTrueRandomnessSeed(ctx, false, 1)
			if err != nil {
				s.logger.Warn("failed to get randomness seed from Aptos Orbital", "err", err)
				// we try to continue with other sources
				continue
			}
			return seed, nil
		case providers.RandSourceLocalGoCrypto:
			seed, err = go_crypto.GenerateRandomSeed(32)
			if err != nil {
				s.logger.Warn("failed to get randomness seed from local go_crypto", "err", err)
				return nil, err
			}
			return seed, nil
		case providers.RandSourceLocalDrivedFromSpaceSeed:
			seed := s.masterSeed.Get()
			if seed == nil {
				return nil, ErrNoMasterSeedSet
			}
			return seed, nil
		default:
			s.logger.Debug("unknown randomness source, skipping", "source", src)
		}
	}

	return nil, err
}

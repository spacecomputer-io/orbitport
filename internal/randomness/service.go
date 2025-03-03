package randomness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/spacecoinxyz/orbitport/internal/config"
	randomness_common "github.com/spacecoinxyz/orbitport/internal/randomness/common"
	"github.com/spacecoinxyz/orbitport/internal/randomness/providers/aptosorbital"
	localrand "github.com/spacecoinxyz/orbitport/internal/randomness/providers/local"
	"github.com/spacecoinxyz/orbitport/internal/utils"
)

const SEED_SIZE = 64

var (
	ErrNoMasterSeedSet = errors.New("no master seed set")
)

// randomnessService implements the randomness service.
type randomnessService struct {
	threadControl utils.ThreadControl
	logger        *utils.Logger

	aptosClient *aptosorbital.AptosClient

	masterSeed         *utils.Locked[*localrand.MasterSeed]
	masterSeedInterval time.Duration
}

// NewService creates a new randomness service.
func NewWithClient(aptosClient *aptosorbital.AptosClient, masterSeedInterval time.Duration, defaultMasterSeed *randomness_common.RandomSeed) randomness_common.Service {
	service := &randomnessService{
		logger:             utils.GetLogger("orbitport:rand:service"),
		aptosClient:        aptosClient,
		threadControl:      utils.NewThreadControl(),
		masterSeed:         utils.NewLocked[*localrand.MasterSeed](nil),
		masterSeedInterval: masterSeedInterval,
	}
	if defaultMasterSeed != nil {
		err := service.updateMasterSeed(context.Background(), defaultMasterSeed)
		if err != nil {
			service.logger.Warn("failed to set default master seed", "err", err)
		}
	}
	return service
}

// / New creates a new randomness service with the given config.
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
	masterSeedRaw := cfg.DefaultMasterSeed
	var defaultMasterSeed *randomness_common.RandomSeed
	if len(masterSeedRaw) > 0 {
		err := json.Unmarshal([]byte(masterSeedRaw), &defaultMasterSeed)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal master seed: %w", err)
		}
	}
	return NewWithClient(aptosClient, cfg.MasterSeedInterval, defaultMasterSeed), nil
}

// Start starts the randomness service background routines:
// 1. update the master seed every masterSeedInterval
func (s *randomnessService) Start(ctx context.Context) error {
	s.threadControl.GoCtx(ctx, func(ctx context.Context) {
		ticker := time.NewTicker(s.masterSeedInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := s.updateMasterSeed(ctx, nil); err != nil {
					s.logger.Warn("could not update master seed", "err", err)
					continue
				}
				s.logger.Debug("updated master seed upon interval", "interval", s.masterSeedInterval)
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
func (s *randomnessService) GetRandomSeed(ctx context.Context, sources ...randomness_common.RandSource) (*randomness_common.RandomSeed, error) {
	if len(sources) == 0 {
		sources = randomness_common.DefaultSources
	}

	s.logger.Debug("getting randomness seed", "sources", sources)

	var seed *randomness_common.RandomSeed
	var err error
	for _, src := range sources {
		switch src {
		case randomness_common.RandSourceAptosOrbital:
			seed, err = s.aptosClient.GetTrueRandomnessSeed(ctx, false, 1)
			if err != nil {
				s.logger.Warn("failed to get randomness seed from Aptos Orbital", "err", err)
				// we try to continue with other sources
				continue
			}
			if seed == nil {
				s.logger.Warn("empty response from Aptos Orbital")
				continue
			}
			if s.masterSeed.Get() == nil {
				// set the master seed if it's not set yet
				_ = s.updateMasterSeed(ctx, seed)
			}
			return seed, nil
		case randomness_common.RandSourceLocalGoCrypto:
			seed, errLocal := localrand.GenerateLocalRandomSeed(SEED_SIZE)
			if errLocal != nil {
				s.logger.Warn("failed to get randomness seed from local go_crypto", "err", errLocal)
				if err == nil {
					err = errLocal
				}
				continue
			}
			return seed, nil
		case randomness_common.RandSourceLocalDrivedFromSpaceSeed:
			mseed := s.masterSeed.Get()
			if mseed == nil {
				s.logger.Debug("no master seed set yet")
				if err == nil {
					err = ErrNoMasterSeedSet
				}
				continue
			}
			seed, err = mseed.Next(SEED_SIZE)
			if err != nil {
				if err == localrand.ErrMasterSeedExhausted {
					s.logger.Warn("master seed exhausted, updating master seed to nil")
					s.masterSeed.Set(nil)
					continue
				}
				s.logger.Warn("failed to get randomness seed from local space seed", "err", err)
				continue
			}
			if mseed.Index() > (localrand.MaxDervied*3)/4 {
				s.logger.Debug("master seed index is high (>75%), updating master seed")
				s.threadControl.Go(func(ctx context.Context) {
					_ = s.updateMasterSeed(ctx, nil)
				})
			}
			return seed, nil
		default:
			s.logger.Debug("unknown randomness source, skipping", "source", src)
		}
	}

	return nil, err
}

// updateMasterSeed updates the master seed with the given seed.
// If seed is nil, it fetches a new seed from the Aptos Orbital API.
func (s *randomnessService) updateMasterSeed(ctx context.Context, seed *randomness_common.RandomSeed) error {
	if seed == nil {
		randSeed, err := s.GetRandomSeed(ctx, randomness_common.RandSourceAptosOrbital)
		if err != nil {
			return fmt.Errorf("failed to get random seed: %v", err)
		}
		seed = randSeed
	}
	if seed == nil || len(seed.Value) == 0 {
		return fmt.Errorf("empty seed")
	}
	masterSeed, err := localrand.NewMasterSeed([]byte(seed.Value))
	if err != nil {
		return fmt.Errorf("failed to create master seed: %v", err)
	}
	s.masterSeed.Set(masterSeed)
	randomness_common.MasterSeedUpdatesTotal.Inc()
	return nil
}

package aptosorbital

import (
	"context"
	"fmt"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	"github.com/spacecomputer-io/orbitport/plugins/proto"
)

// Plugin implements the interfaces for the Aptos Orbital API.
type Plugin struct {
	proto.RandomnessPluginServer

	aptosClient  *AptosClient
	masterSeeds  []MasterSeed
	seedInterval int64
}

// NewPlugin creates a new Aptos Orbital plugin.
func NewPlugin() (*Plugin, error) {
	cfg := readFromEnv()
	LoadMasterSeedConfig(cfg)
	defaultMasterSeed := cfg.AptosOrbitalDefaultMasterSeed

	logger := utils.GetLogger("orbitport:aptosorbital")
	logger.Infof("creating plugin with API url=%s, auth url=%s, client id=%s",
		cfg.AptosOrbitalApiUrl,
		cfg.AptosOrbitalAuthUrl,
		cfg.AptosOrbitalClientId,
	)

	aptosClient, err := NewClient(
		WithApiURL(cfg.AptosOrbitalApiUrl),
		WithAuthURL(cfg.AptosOrbitalAuthUrl),
		WithClientID(cfg.AptosOrbitalClientId),
		WithClientSecret(cfg.AptosOrbitalClientSecret),
		WithRateLimit(float64(cfg.AptosOrbitalRateLimit), 2),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Aptos Orbital client: %w", err)
	}

	p := &Plugin{
		aptosClient:  aptosClient,
		masterSeeds:  make([]MasterSeed, 0, MaxMasterSeeds),
		seedInterval: cfg.AptosOrbitalSeedPeriod,
	}

	p.StartSeedFetch(context.Background(), defaultMasterSeed)
	return p, nil
}

func (p *Plugin) StartSeedFetch(ctx context.Context, defaulMastertSeed string) {
	logger := utils.GetLogger("orbitport:aptosorbital")
	logger.Infof("Starting master seed fetcher with interval %d sec", p.seedInterval)

	logger.Debugf("Inserting Default Master Seed %s", defaulMastertSeed)
	p.addMasterSeed(defaulMastertSeed)

	go func() {
		ticker := time.NewTicker(time.Duration(p.seedInterval) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				logger.Info("Stopping master seed fetcher")
				return
			case <-ticker.C:
				ctxTimeout, cancel := context.WithTimeout(ctx, 10*time.Second)
				seedResp, err := p.aptosClient.GetTrueRandomnessSeed(ctxTimeout, true, 1)
				cancel()

				if err == nil && seedResp != nil && len(seedResp.Values) > 0 {
					seed := seedResp.Values[0]
					p.addMasterSeed(seed)
					logger.Debugf("Fetched new master seed (%d total)", len(p.masterSeeds))
				} else {
					logger.Warnf("Failed to fetch master seed from Aptos: %v", err)
					continue
				}
			}
		}
	}()
}

// GetTrng handles the GetTrng RPC call.
// It retrieves a true randomness seed from the Aptos Orbital API.
// The request contains the number of chunks to retrieve and whether to ignore the signature.
func (p *Plugin) GetTrng(ctx context.Context, req *proto.TrngRequest) (*proto.TrngResponse, error) {
	logger := utils.GetLogger("orbitport:aptosorbital:gettrng")
	numChunk := int(req.Chunks)
	// defaults to 1 if numChunk is 0
	if numChunk == 0 {
		numChunk = 1
	}

	// first attempt retrieving real aptos rng val
	resp, err := p.aptosClient.GetTrueRandomnessSeed(ctx, req.IgnoreSig, uint(numChunk))
	if err == nil && resp != nil {
		values := resp.GetValues()
		if len(values) > 0 {
			ctrngFreshTotal.WithLabelValues("aptosorbital").Add(float64(len(values)))
		}
		return resp, nil
	}

	// second fallback if aptos fails
	logger.Warnf("Aptos failed to deliver fresh rng, falling back to master seeds: %v", err)

	masterSeed := p.pickMasterSeed()
	if masterSeed == nil {
		return nil, fmt.Errorf("no master seeds available for fallback and aptos faileed: %v", err)
	}

	derived, err := masterSeed.DeriveBulk(numChunk)
	logger.Debugf("rngs derived from master seed: %s", derived)
	if err != nil {
		return nil, fmt.Errorf("failed to derivee bulk valuese: %v", err)
	}

	ctrngFallbackTotal.WithLabelValues("aptosorbital").Add(float64(len(derived)))

	return &proto.TrngResponse{Values: derived, Sig: ""}, nil
}

func (p *Plugin) addMasterSeed(seed string) {
	if seed == "" {
		return
	}

	m := MasterSeed{Seed: seed}
	if _, err := m.Derive(0); err != nil {
		return
	}

	p.masterSeeds = append(p.masterSeeds, m)
	if len(p.masterSeeds) >= MaxMasterSeeds {
		p.masterSeeds = p.masterSeeds[1:]
	}
}

func (p *Plugin) pickMasterSeed() *MasterSeed {
	if len(p.masterSeeds) == 0 {
		return nil
	}

	idx := time.Now().UnixNano() % int64(len(p.masterSeeds))
	return &p.masterSeeds[idx]
}

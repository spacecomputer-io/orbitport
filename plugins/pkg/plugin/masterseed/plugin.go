package masterseed

import (
	"context"
	"fmt"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	"github.com/spacecomputer-io/orbitport/plugins/proto"
	"google.golang.org/grpc"
)

type Plugin struct {
	proto.MasterSeedPluginServer
	aptosConn    *grpc.ClientConn
	aptosClient  proto.RandomnessPluginClient
	masterSeeds  []MasterSeed
	seedInterval time.Duration
}

// NewPlugin creates a new masterseed plugin instance.
func NewPlugin() (*Plugin, error) {
	cfg := readFromEnv()
	LoadMasterSeedConfig(cfg)
	defaultMasterSeeds := cfg.MasterSeedDefaultMasterSeeds

	conn, aptosClient, err := getAptosPluginClient(*cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to init aptos client: %w", err)
	}

	p := &Plugin{
		aptosConn:    conn,
		aptosClient:  aptosClient,
		masterSeeds:  make([]MasterSeed, 0, MaxMasterSeeds),
		seedInterval: time.Duration(cfg.MaserSeedPeriod),
	}

	// start background fetch loop
	p.startSeedFetch(context.Background(), defaultMasterSeeds)
	return p, nil
}

func (p *Plugin) Close() error {
	logger := utils.GetLogger("orbitport:masterseed")
	logger.Info("Stopping masterseed plugin...")

	if p.aptosConn != nil {
		if err := p.aptosConn.Close(); err != nil {
			logger.Errorf("error closing aptos client connection: %v", err)
			return err
		}
	}
	return nil
}

func (p *Plugin) startSeedFetch(ctx context.Context, defaulMastertSeeds []string) {
	logger := utils.GetLogger("orbitport:masterseed")
	logger.Infof("Starting master seed fetcher with interval %d sec", p.seedInterval)

	logger.Infof("Inserting %d Default Master Seeds...", len(defaulMastertSeeds))
	for _, s := range defaulMastertSeeds {
		p.addMasterSeed(s)
	}

	logger.Infof("Master seed plugin initialized with %d default master seeds", len(p.masterSeeds))

	go func() {
		ticker := time.NewTicker(time.Duration(p.seedInterval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				logger.Info("Stopping master seed fetcher")
				return
			case <-ticker.C:
				resp, err := p.aptosClient.GetTrng(ctx, &proto.TrngRequest{
					IgnoreSig: true,
					Chunks:    1,
				})
				if err != nil || len(resp.GetValues()) == 0 {
					logger.Warnf("Failed to fetch master seed from aptos: %v", err)
					continue
				}

				seed := resp.GetValues()[0]
				p.addMasterSeed(seed)
				logger.Debugf("Fetched new master seed (%d total)", len(p.masterSeeds))
			}
		}
	}()
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
	if len(p.masterSeeds) > MaxMasterSeeds {
		p.masterSeeds = p.masterSeeds[1:]
	}
}

// crypto/rang ensures uniform distribution during seed selection
func (p *Plugin) pickMasterSeed() (*MasterSeed, error) {
	if len(p.masterSeeds) == 0 {
		return nil, fmt.Errorf("no master seed available")
	}

	rnd, err := randIndex()
	if err != nil {
		// fallback to simple time-based modulo
		return nil, fmt.Errorf("failed to generate secure random index: %w", err)
	}

	idx := int(rnd) % len(p.masterSeeds)
	return &p.masterSeeds[idx], nil
}

// GetSeeds implements the MasterSeedPlugin gRPC service.
func (p *Plugin) GetSeeds(ctx context.Context, req *proto.GetSeedsRequest) (*proto.GetSeedsResponse, error) {
	logger := utils.GetLogger("orbitport:masterseed:getseeds")

	count := int(req.GetCount())
	if count <= 0 {
		count = 1
	}

	// use stored master seeds
	logger.Debugf("Deriving %d seeds from stored master seeds", count)
	if len(p.masterSeeds) == 0 {
		return nil, fmt.Errorf("no master seeds available")
	}

	master, err := p.pickMasterSeed()
	if err != nil {
		logger.Errorf("pickMasterSeed failed: %v", err)
		return nil, err
	}
	logger.Debugf("Using master seed: %.4s...", master.Seed)

	derived, err := master.DeriveBulk(count)
	if err != nil {
		return nil, fmt.Errorf("failed to derive seeds: %w", err)
	}

	logger.Debugf("Returning %d derived seeds (derived from stored CTRNG seeds)", len(derived))
	return &proto.GetSeedsResponse{
		Values: derived,
	}, nil
}

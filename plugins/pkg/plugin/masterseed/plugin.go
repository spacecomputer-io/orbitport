package masterseed

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
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
	mu           sync.RWMutex
	seedInterval time.Duration
	deriveSeq    atomic.Uint64
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

	if _, err := m.parseTRNGBlock(); err != nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.masterSeeds = append(p.masterSeeds, m)
	if len(p.masterSeeds) > MaxMasterSeeds {
		p.masterSeeds = p.masterSeeds[1:]
	}
}

// cryptoRandIndex returns a uniform random integer in [0, n), using rejection sampling to avoid modulo bias.
func cryptoRandIndex(n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("invalid n=%d", n)
	}
	un := uint32(n)

	const maxU32 = ^uint32(0)
	limit := maxU32 - (maxU32 % un)

	var buf [4]byte
	for {
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, fmt.Errorf("crypto/rand failed: %w", err)
		}
		v := binary.LittleEndian.Uint32(buf[:])
		if v < limit {
			return int(v % un), nil
		}
	}
}

// crypto/rang ensures uniform distribution during seed selection
func (p *Plugin) pickMasterSeed() (MasterSeed, error) {
	p.mu.RLock()
	count := len(p.masterSeeds)
	p.mu.RUnlock()

	if count == 0 {
		return MasterSeed{}, fmt.Errorf("no master seed available")
	}

	idx, err := cryptoRandIndex(count)
	if err != nil {
		return MasterSeed{}, fmt.Errorf("failed to generate secure random index: %w", err)
	}

	p.mu.RLock()
	m := p.masterSeeds[idx]
	p.mu.RUnlock()
	return m, nil
}

// GetSeeds implements the MasterSeedPlugin gRPC service.
func (p *Plugin) GetSeeds(ctx context.Context, req *proto.GetSeedsRequest) (*proto.GetSeedsResponse, error) {
	logger := utils.GetLogger("orbitport:masterseed:getseeds")

	count := int(req.GetCount())
	if count <= 0 {
		count = 1
	}

	// Context required for Mode A domain separation
	logger.Debugf("Deriving %d seeds from stored master seeds", count)

	master, err := p.pickMasterSeed()
	if err != nil {
		logger.Errorf("pickMasterSeed failed: %v", err)
		return nil, err
	}
	logger.Debugf("Using master seed: %.4s...", master.Seed)

	// Uniqueness inputs
	nonceNanos := time.Now().UnixNano()
	seq := p.deriveSeq.Add(1)

	derived, err := master.DeriveBulkWithNonce(count, nonceNanos, seq)
	if err != nil {
		return nil, fmt.Errorf("failed to derive seeds: %w", err)
	}

	logger.Debugf("Returning %d derived seeds (derived from stored CTRNG seeds)", len(derived))
	return &proto.GetSeedsResponse{
		Values: derived,
	}, nil
}

package masterseed

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"
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
		seedInterval: time.Duration(cfg.MaserSeedPeriod) * time.Second,
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
	logger.Infof("Starting master seed fetcher with interval %d sec", int(p.seedInterval/time.Second))

	bootNonceNanos := time.Now().UnixNano()

	logger.Infof("Inserting %d Default Master Seeds (boot-salted)...", len(defaulMastertSeeds))
	for _, s := range defaulMastertSeeds {
		salted, err := saltDefaultSeed(s, bootNonceNanos)
		if err != nil {
			logger.Warnf("Failed to salt default seed: %v", err)
			continue
		}
		p.addMasterSeed(salted)
	}

	logger.Infof("Master seed plugin initialized with %d default master seeds", len(p.masterSeeds))

	go func() {
		ticker := time.NewTicker(p.seedInterval)
		logger.Infof("Starting master seed fetcher with interval %d sec", int(p.seedInterval/time.Second))
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
				logger.Debugf("Fetched new master seed (%d total)", p.masterSeedCount())
			}
		}
	}()
}

func (p *Plugin) masterSeedCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.masterSeeds)
}

func (p *Plugin) addMasterSeed(seed string) {
	if seed == "" {
		return
	}
	m := MasterSeed{Seed: seed, Offset: 0}

	if _, err := m.parseTRNGBlock(); err != nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.masterSeeds = append(p.masterSeeds, m)
	if len(p.masterSeeds) > MaxMasterSeeds {
		copy(p.masterSeeds[0:], p.masterSeeds[1:])
		// zero out the last element so old references are dropped
		p.masterSeeds[len(p.masterSeeds)-1] = MasterSeed{}
		p.masterSeeds = p.masterSeeds[:len(p.masterSeeds)-1]
	}
}

// saltDefaultSeed takes a hex seed block (32 bytes) and produces a new 32-byte seed block:
// SHA256(seedBlock || BE(bootNonceNanos)).
// used for default seeds so that each boot instance igests different default seeds.
func saltDefaultSeed(seedHex string, bootNonceNanos int64) (string, error) {
	raw, err := hex.DecodeString(seedHex)
	if err != nil {
		return "", fmt.Errorf("default seed is not valid hex: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("default seed length is %d bytes; expected 32", len(raw))
	}

	h := sha256.New()
	h.Write(raw)

	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], uint64(bootNonceNanos))
	h.Write(nb[:])

	sum := h.Sum(nil) // 32 bytes for SHA-256
	return hex.EncodeToString(sum[:32]), nil
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

// reserveSeedOffset reserves a block of bytes from one of the stored master seeds,
// returning the seed hex and the starting offset for derivation.
// The caller is responsible for deriving the required number of outputs
// from the returned seed and offset.
// This method updates the internal offset cursor for the selected master seed.
// It uses crypto/rand to select a random master seed to ensure uniform distribution
// when multiple clients are requesting seeds concurrently.
func (p *Plugin) reserveSeedOffset(count int) (seedHex string, startOffset uint64, err error) {
	logger := utils.GetLogger("orbitport:masterseed:reserve")

	outLen := TRNGSize
	if outLen <= 0 || outLen > 1024 {
		outLen = 32
	}
	if count <= 0 {
		return "", 0, fmt.Errorf("invalid count=%d", count)
	}

	// Hard cap to prevent runaway CPU/memory and gRPC response explosions.
	if count > MaxCountPerRequest {
		return "", 0, fmt.Errorf("count too large: %d (max %d)", count, MaxCountPerRequest)
	}

	need, ok := mulUint64Checked(uint64(count), uint64(outLen))
	if !ok {
		return "", 0, fmt.Errorf("byte requirement overflow: count=%d outLen=%d", count, outLen)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.masterSeeds) == 0 {
		return "", 0, fmt.Errorf("no master seed available")
	}

	idx, err := cryptoRandIndex(len(p.masterSeeds))
	if err != nil {
		return "", 0, err
	}

	seedHex = p.masterSeeds[idx].Seed
	start := p.masterSeeds[idx].Offset
	end, ok := addUint64Checked(start, need)
	if !ok {
		return "", 0, fmt.Errorf("seed offset overflow: start=%d need=%d", start, need)
	}

	p.masterSeeds[idx].Offset = end

	logger.Debugf(
		"Reserved seed %.4s... idx=%d range=[%d,%d) need=%d bytes (count=%d outLen=%d)",
		seedHex, idx, start, end, need, count, outLen,
	)

	return seedHex, start, nil
}

// GetSeeds implements the MasterSeedPlugin gRPC service.
func (p *Plugin) GetSeeds(ctx context.Context, req *proto.GetSeedsRequest) (*proto.GetSeedsResponse, error) {
	logger := utils.GetLogger("orbitport:masterseed:getseeds")

	count := int(req.GetCount())
	if count <= 0 {
		count = 1
	}

	seedHex, startOff, err := p.reserveSeedOffset(count)
	if err != nil {
		logger.Errorf("reserveSeedOffset failed: %v", err)
		return nil, err
	}
	logger.Debugf("Using master seed: %.4s... offset=%d", seedHex, startOff)
	logger.Debugf("Deriving %d seeds from stored master seeds", count)

	ms := MasterSeed{Seed: seedHex} // Offset field unused here
	derived, err := ms.DeriveBulkAtOffset(count, startOff)
	if err != nil {
		return nil, fmt.Errorf("failed to derive seeds: %w", err)
	}

	return &proto.GetSeedsResponse{Values: derived}, nil
}

// helpers that check for uint64 multiplication overflow and addition overflow.
const maxUint64 = ^uint64(0)

func mulUint64Checked(a, b uint64) (uint64, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}
	if a > maxUint64/b {
		return 0, false
	}
	return a * b, true
}

func addUint64Checked(a, b uint64) (uint64, bool) {
	if a > maxUint64-b {
		return 0, false
	}
	return a + b, true
}

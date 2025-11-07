package beacon

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/core/health"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	"github.com/spacecomputer-io/orbitport/plugins/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Plugin struct {
	cfg Config

	registry *Registry

	scheduler *Scheduler
	builder   *Builder
}

// NewPlugin creates a new Beacon plugin with a storage layer.
func NewPlugin() (*Plugin, error) {
	ctx := context.Background()
	cfg := readFromEnv()

	logger := utils.GetLogger("orbitport:beacon")
	logger.Infof("Creating plugin with config: %+v", cfg)

	err := health.WaitForDependencies(ctx, time.Second, time.Duration(60*time.Second), cfg.IPFSPlugin, cfg.CTRNGPlugin, cfg.MasterSeedPlugin)
	if err != nil {
		return nil, fmt.Errorf("beacon plugin dependencies failed to start within the alloted timeframe, aborting: %w", err)
	}

	registry, err := loadRegistry(context.Background(), cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to load beacon registry: %w", err)
	}
	scheduler := NewScheduler(cfg, registry)
	// Initialize the plugin with the configuration
	plugin := &Plugin{
		cfg:       cfg,
		registry:  registry,
		scheduler: scheduler,
		builder:   NewBuilder(scheduler),
	}

	return plugin, nil
}

// Start starts the beacon plugin, spwawning background tasks for scheduling beacon updates.
func (p *Plugin) Start(ctx context.Context) error {
	logger := utils.GetLogger("orbitport:beacon")

	logger.Info("Starting beacon plugin...")

	if err := p.scheduler.Start(ctx); err != nil {
		return fmt.Errorf("failed to start beacon scheduler: %w", err)
	}
	logger.Info("Beacon scheduler started")

	if err := p.builder.Start(ctx); err != nil {
		return fmt.Errorf("failed to start beacon builder: %w", err)
	}
	logger.Info("Beacon builder started")

	return nil
}

// Stop stops the beacon plugin, cleaning up resources.
func (p *Plugin) Close() error {
	logger := utils.GetLogger("orbitport:beacon")
	logger.Info("Stopping beacon plugin...")

	_ = p.scheduler.Close()
	_ = p.builder.Close()

	return nil
}

func loadLastBeaconBlock(ctx context.Context, ipfsPluginClient proto.IpfsPluginClient, name string) (string, *BeaconPayload, error) {

	logger := utils.GetLogger("orbitport:beacon")
	getResp, err := ipfsPluginClient.Get(ctx, &proto.GetRequest{
		Key:       name,
		Namespace: "ipns",
	})
	if err != nil {
		// TODO: Handle error appropriately, maybe retry or set to recoverable state
		return "", nil, fmt.Errorf("failed to get beacon from IPFS: %v", err)
	}
	lastCid := getResp.GetPath()
	logger.Infof("retrieved last beacon block CID: %s", lastCid)
	block, err := UnmarshalBeaconBlock(getResp.GetData())
	if err != nil {
		return "", nil, fmt.Errorf("failed to unmarshal beacon block: %w", err)
	}

	return lastCid, block.Data, nil
}

// creates a new beacon in ipfs and returns its ipns public key
// Two-step genesis: A. pubKey acquisition, B. final genesis
func createBeacon(ctx context.Context, ipfsPluginClient proto.IpfsPluginClient, beaconName string, msg string, interval int32) (BeaconMetadata, error) {
	logger := utils.GetLogger("orbitport:beacon")

	// A. temp genesis (no metadata)
	gen0 := &BeaconPayload{Sequence: 0, Timestamp: time.Now().Unix(), CTRNG: []string{}}
	tempBlock := Block{Link: "", Data: gen0}
	tempBytes, err := json.Marshal(tempBlock)
	if err != nil {
		genesisStepTotal.WithLabelValues(beaconName, "temp_add", "failed").Inc()
		return BeaconMetadata{}, fmt.Errorf("marshal temp genesis: %w", err)
	}
	genesisStepTotal.WithLabelValues(beaconName, "temp_add", "success").Inc()

	t := prometheus.NewTimer(genesisStepDuration.WithLabelValues(beaconName, "temp_add"))
	addTemp, err := ipfsPluginClient.Add(ctx, &proto.AddRequest{Data: tempBytes})
	t.ObserveDuration()
	if err != nil {
		return BeaconMetadata{}, fmt.Errorf("add temp genesis: %w", err)
	}

	t = prometheus.NewTimer(genesisStepDuration.WithLabelValues(beaconName, "temp_publish"))
	pubResp, err := ipfsPluginClient.Publish(ctx, &proto.PublishRequest{
		Cid:         addTemp.Cid,
		PublishName: beaconName,
	})
	t.ObserveDuration()
	if err != nil {
		genesisStepTotal.WithLabelValues(beaconName, "temp_publish", "failed").Inc()
		return BeaconMetadata{}, fmt.Errorf("publish temp genesis to IPNS: %w", err)
	}
	genesisStepTotal.WithLabelValues(beaconName, "temp_publish", "success").Inc()

	pubKey := pubResp.IpnsName
	logger.Infof("temp genesis published for %q; acquired pubkey %s", beaconName, pubKey)

	var beaconInterval time.Duration
	if interval > 0 {
		beaconInterval = time.Duration(interval) * time.Second
	} else {
		beaconInterval = 60 * time.Second
	}

	meta := &BeaconMetadata{
		Name:      beaconName,
		PublicKey: pubKey,
		Version:   "1.0",
		Encoding:  "json",
		BatchSize: 3,
		Message:   msg,
		Interval:  beaconInterval,
	}

	finalBlock := Block{
		Link:     "",
		Data:     gen0,
		Metadata: meta,
	}
	finalBytes, err := json.Marshal(finalBlock)
	if err != nil {
		return BeaconMetadata{}, fmt.Errorf("marshal final genesis: %w", err)
	}
	t = prometheus.NewTimer(genesisStepDuration.WithLabelValues(beaconName, "final_add"))
	addFinal, err := ipfsPluginClient.Add(ctx, &proto.AddRequest{Data: finalBytes})
	t.ObserveDuration()

	if err != nil {
		genesisStepTotal.WithLabelValues(beaconName, "final_add", "failed").Inc()
		return BeaconMetadata{}, fmt.Errorf("add final genesis: %w", err)
	}
	genesisStepTotal.WithLabelValues(beaconName, "final_add", "success").Inc()

	// Republish to reference the final genesis CID in IPNS (removes reference to temp genesis)
	t = prometheus.NewTimer(genesisStepDuration.WithLabelValues(beaconName, "final_publish"))
	_, err = ipfsPluginClient.Publish(ctx, &proto.PublishRequest{
		Cid:         addFinal.Cid,
		PublishName: beaconName,
	})
	t.ObserveDuration()

	if err != nil {
		genesisStepTotal.WithLabelValues(beaconName, "final_publish", "failed").Inc()
		return BeaconMetadata{}, fmt.Errorf("publish final genesis to IPNS: %w", err)
	}

	genesisStepTotal.WithLabelValues(beaconName, "final_publish", "success").Inc()
	logger.Infof("final genesis published for %q (CID %s) with metadata; pubkey %s", beaconName, addFinal.Cid, pubKey)

	return *meta, nil
}

// loadRegistry initializes the plugin, loading (or creating) the persisted registry.
func loadRegistry(ctx context.Context, cfg Config) (*Registry, error) {
	logger := utils.GetLogger("orbitport:beacon:registry_loader")

	conn, ipfs, err := getIpfsPluginClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to IPFS plugin: %w", err)
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			logger.Errorf("error closing ipfs plugin connection: %v", cerr)
		}
	}()

	// persisted registry state identifier
	registryAlias := cfg.BeaconRegistry
	if registryAlias == "" {
		return nil, fmt.Errorf("BEACON_REGISTRY must be set (e.g., \"orbitport-registry\")")
	}

	reg, _, exists, err := queryRegistry(ctx, ipfs, registryAlias)
	if err != nil {
		return nil, fmt.Errorf("fetch %v failed: %w", registryAlias, err)
	}

	beaconName := cfg.DefaultBeaconName

	if exists {
		// If the registry exists, reuse the beacon if present
		if meta, ok := findBeaconInRegistry(reg, beaconName); ok {
			logger.Infof("Found beacon %q in registry %q; resuming.", beaconName, registryAlias)
			return &Registry{Beacons: []BeaconMetadata{meta}}, nil
		}
		logger.Infof("Beacon %q not in registry %q; creating and upserting.", beaconName, registryAlias)
	} else {
		logger.Infof("Registry %q not found; will create it.", registryAlias)
		reg = &Registry{Beacons: []BeaconMetadata{}}
	}

	// Create the beacon (two-step genesis), then upsert into the registry and publish
	meta, err := createBeacon(ctx, ipfs, beaconName, cfg.BeaconMsg, cfg.BeaconInterval)
	if err != nil {
		return nil, fmt.Errorf("createBeacon(%q) failed: %w", beaconName, err)
	}

	upsertBeacon(&reg.Beacons, meta)

	if _, err := publishRegistry(ctx, ipfs, registryAlias, reg); err != nil {
		return nil, fmt.Errorf("publishRegistry(%q) failed: %w", registryAlias, err)
	}
	logger.Infof("Upserted beacon %q into registry %q", beaconName, registryAlias)

	return &Registry{Beacons: []BeaconMetadata{meta}}, nil
}

func getIpfsPluginClient(cfg Config) (*grpc.ClientConn, proto.IpfsPluginClient, error) {
	conn, err := grpc.NewClient(cfg.IPFSPlugin, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to IPFS plugin: %w", err)
	}

	client := proto.NewIpfsPluginClient(conn)
	return conn, client, nil
}

func getCtrngPluginClient(cfg Config) (*grpc.ClientConn, proto.RandomnessPluginClient, error) {
	conn, err := grpc.NewClient(cfg.CTRNGPlugin, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to CTRNG plugin: %w", err)
	}

	client := proto.NewRandomnessPluginClient(conn)
	return conn, client, nil
}

func getMasterSeedPluginClient(cfg Config) (*grpc.ClientConn, proto.MasterSeedPluginClient, error) {
	conn, err := grpc.NewClient(cfg.MasterSeedPlugin, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to MasterSeed plugin: %w", err)
	}
	client := proto.NewMasterSeedPluginClient(conn)
	return conn, client, nil
}

// queryRegistry tries to fetch the Orbitport registry JSON from IPNS <alias>.
func queryRegistry(ctx context.Context, ipfs proto.IpfsPluginClient, alias string) (*Registry, string, bool, error) {
	logger := utils.GetLogger("orbitport:beacon:registry_query")

	gctx, gcancel := context.WithTimeout(ctx, 20*time.Second)
	defer gcancel()

	// Alias -> IPNS name (PeerID) via KeyInfo
	ki, err := ipfs.KeyInfo(gctx, &proto.KeyInfoRequest{PublishName: alias}, grpc.WaitForReady(true))
	if err != nil || ki == nil || ki.IpnsName == "" {
		// Alias not present yet or never published
		logger.Warnf("KeyInfo(%v) unavailable: %v", alias, err)
		return nil, "", false, nil
	}

	// Resolve current head of the registry
	resp, err := ipfs.Get(gctx, &proto.GetRequest{
		// key is "/ipns/<peerID>"
		Key:       ki.IpnsName,
		Namespace: "ipns",
	}, grpc.WaitForReady(true))
	if err != nil {
		// Alias exists but nothing published yet
		logger.Warnf("Get(%s) failed: %v", ki.IpnsName, err)
		return nil, "", false, nil
	}

	var reg Registry
	if err := reg.Unmarshal(resp.GetData()); err != nil {
		return nil, "", true, fmt.Errorf("unmarshal registry: %w", err)
	}

	return &reg, resp.GetPath(), true, nil
}

func findBeaconInRegistry(reg *Registry, name string) (BeaconMetadata, bool) {
	for _, b := range reg.Beacons {
		if b.Name == name {
			return b, true
		}
	}
	return BeaconMetadata{}, false
}

func upsertBeacon(list *[]BeaconMetadata, meta BeaconMetadata) {
	for i := range *list {
		if (*list)[i].Name == meta.Name {
			(*list)[i] = meta
			return
		}
	}
	*list = append(*list, meta)
}

func publishRegistry(ctx context.Context, ipfs proto.IpfsPluginClient, alias string, reg *Registry) (string, error) {
	logger := utils.GetLogger("orbitport:beacon:registry_publish")

	bytes, err := reg.Marshal()
	if err != nil {
		return "", fmt.Errorf("marshal registry: %v", err)
	}

	addResp, err := ipfs.Add(ctx, &proto.AddRequest{Data: bytes})
	if err != nil {
		return "", fmt.Errorf("ipfs add registry: %v", err)
	}

	// create alias key if it doesn't exist, then publish the registry head
	_, err = ipfs.Publish(ctx, &proto.PublishRequest{
		Cid:         addResp.Cid,
		PublishName: alias,
	})
	if err != nil {
		return "", fmt.Errorf("publish registry %v: %v", alias, err)
	}

	logger.Infof("Published registry %v -> CID %s", alias, addResp.Cid)
	return addResp.Cid, nil
}

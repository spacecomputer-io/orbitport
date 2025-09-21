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

	err := health.WaitForDependencies(ctx, time.Second, time.Duration(60*time.Second), cfg.IPFSPlugin, cfg.CTRNGPlugin)
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
func createBeacon(ctx context.Context, ipfsPluginClient proto.IpfsPluginClient, beaconName string, msg string) (BeaconMetadata, error) {
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

	// B. final genesis with metadata
	meta := &BeaconMetadata{
		Name:      beaconName,
		PublicKey: pubKey,
		Version:   "1.0",
		Encoding:  "json",
		BatchSize: 3,
		Message:   msg,
		Interval:  10 * time.Second,
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

// init initializes the plugin, loading beacons from the registry.
func loadRegistry(ctx context.Context, cfg Config) (*Registry, error) {
	logger := utils.GetLogger("orbitport:beacon:registry_loader")

	conn, ipfsPluginClient, err := getIpfsPluginClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to IPFS plugin: %w", err)
	}
	defer func() {
		err = conn.Close()
		if err != nil {
			logger.Errorf("error closing ipfs plugin connection: %v", err)
		}
	}()

	if len(cfg.BeaconRegistry) == 0 {
		beaconName := "default-beacon2.4"
		msg := cfg.BeaconMsg
		logger.Info("No beacon registry configured. Creating new registry with genesis block")
		beaconMetadata, err := createBeacon(ctx, ipfsPluginClient, beaconName, msg)
		if err != nil {
			return nil, fmt.Errorf("failed to create new beacon for new registry: %w", err)
		}

		logger.Infof("Registry created. Name: %s, PublicKey: %s", beaconMetadata.Name, beaconMetadata.PublicKey)
		return &Registry{
			Beacons: []BeaconMetadata{
				beaconMetadata,
			},
		}, nil
	}

	logger.Info("beacon registry key acquired from config")
	getResp, err := ipfsPluginClient.Get(ctx, &proto.GetRequest{
		Key:       cfg.BeaconRegistry,
		Namespace: "ipns",
	}, grpc.WaitForReady(true))
	if err != nil {
		return nil, fmt.Errorf("failed to get beacon registry from IPFS: %w", err)
	}
	logger.Info("Successfully retrieved beacon registry from IPFS")

	registry := new(Registry)
	err = registry.Unmarshal(getResp.GetData())
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal beacon registry: %w", err)
	}
	logger.Infof("Loaded %d beacons from registry", len(registry.Beacons))

	return registry, nil
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

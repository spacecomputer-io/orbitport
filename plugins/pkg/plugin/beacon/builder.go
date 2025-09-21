package beacon

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	"github.com/spacecomputer-io/orbitport/plugins/proto"
)

type Builder struct {
	threads utils.ThreadControl
	cfg     Config

	scheduler *Scheduler
}

// NewBuilder creates a new Builder instance for the beacon plugin.
func NewBuilder(scheduler *Scheduler) *Builder {
	return &Builder{
		threads:   utils.NewThreadControl(),
		cfg:       readFromEnv(),
		scheduler: scheduler,
	}
}

// Start starts the beacon builder, which will periodically execute beacons.
func (b *Builder) Start(_ context.Context) error {
	logger := utils.GetLogger("orbitport:beacon:builder")
	logger.Info("Starting beacon builder...")

	ipfsConn, ipfsPluginClient, err := getIpfsPluginClient(b.cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to IPFS plugin: %v", err)
	}
	ctrngConn, ctrngPluginClient, err := getCtrngPluginClient(b.cfg)
	if err != nil {
		err = ipfsConn.Close()
		if err != nil {
			logger.Errorf("error closing ipfs client connection: %v", err)
		}
		return fmt.Errorf("failed to connect to CTRNG plugin: %v", err)
	}
	q := b.scheduler.Queue()
	// execution loop for beacon updates/execution
	b.threads.Go(func(ctx context.Context) {
		defer func() {
			err = ipfsConn.Close()
			if err != nil {
				logger.Errorf("error closing ipfs client connection: %v", err)
			}
			err = ctrngConn.Close()
			if err != nil {
				logger.Errorf("error closing ctrng client connection: %v", err)
			}
		}()

		logger.Info("Connected to IPFS plugin, waiting for beacon updates...")

		for {
			select {
			case <-ctx.Done():
				logger.Info("Stopping beacon execution listener")
				return
			case event := <-q:
				b.threads.GoCtx(ctx, func(ctx context.Context) {
					err := b.executeBeacon(ctx, event, ctrngPluginClient, ipfsPluginClient)
					if err != nil {
						execTotal.WithLabelValues(event.Name, "failed").Inc()
						logger.Errorf("Failed to execute beacon %s: %v", event.Name, err)
						// TODO: Handle error appropriately, maybe retry or set to recoverable state
					}
				})
			}
		}
	})

	return nil
}

func (b *Builder) Close() error {
	logger := utils.GetLogger("orbitport:beacon:builder")
	logger.Info("Stopping beacon builder...")

	// Stop all background threads
	b.threads.Close()

	return nil
}

func (b *Builder) executeBeacon(c context.Context, metadata BeaconMetadata, ctrngPluginClient proto.RandomnessPluginClient, ipfsPluginClient proto.IpfsPluginClient) error {
	ctx, cancel := context.WithTimeout(c, time.Minute*1)
	defer cancel()

	logger := utils.GetLogger("orbitport:beacon:executor").With("beacon", metadata.Name)
	execTimer := prometheus.NewTimer(execDuration.WithLabelValues(metadata.Name))
	defer execTimer.ObserveDuration()

	logger.Infof("Executing beacon for metadata: %+v", metadata)

	resp := loadCtrngs(ctx, b.threads, ctrngPluginClient, metadata)

	loadTimer := prometheus.NewTimer(loadLastDuration.WithLabelValues(metadata.Name))
	lastCid, lastBlock, err := loadLastBeaconBlock(ctx, ipfsPluginClient, metadata.Name)
	loadTimer.ObserveDuration()
	if err != nil {
		// drain the channel
		// TODO: Handle error appropriately, maybe retry strategy or store the ctrngs for later
		loadLastTotal.WithLabelValues(metadata.Name, "failed").Inc()
		execErr := fmt.Errorf("failed to load last beacon block: %w", err)
		logger.Errorf("%v", execErr)

		select {
		case <-resp:
		default:
		}
		return execErr
	}

	loadLastTotal.WithLabelValues(metadata.Name, "success").Inc()
	logger.Infof("Last beacon (%s) block CID: %s, Sequence: %d", metadata.Name, lastCid, lastBlock.Sequence)

	ctrngs := <-resp
	if len(ctrngs) == 0 {
		logger.Warnf("Beacon %s: received empty CTRNG slice", metadata.Name)
		return fmt.Errorf("no CTRNG values received for beacon %s", metadata.Name)
	}

	logger.Debugf("Loaded %d CTRNG values for beacon %s", len(ctrngs), metadata.Name)
	for i, v := range ctrngs {
		logger.Debugf("  CTRNG[%d]: %s", i, v)
	}

	beaconPayload := &BeaconPayload{
		Sequence:  lastBlock.Sequence + 1,
		Timestamp: time.Now().Unix(),
		CTRNG:     ctrngs,
	}

	logger.Debugf("Beacon payload: %+v", beaconPayload)

	block := Block{
		Link: lastCid,
		Data: beaconPayload,
	}

	blockBytes, err := json.Marshal(block)
	if err != nil {
		return fmt.Errorf("failed to marshal beacon block: %v", err)
	}

	logger.Debugf("Beacon block JSON: %s", string(blockBytes))

	// Save block to IPFS
	addTimer := prometheus.NewTimer(ipfsAddDuration.WithLabelValues(metadata.Name))
	addResp, err := ipfsPluginClient.Add(ctx, &proto.AddRequest{
		Data: blockBytes,
	})
	addTimer.ObserveDuration()

	if err != nil {
		ipfsAddTotal.WithLabelValues(metadata.Name, "failed").Inc()
		return fmt.Errorf("failed to add beacon block to IPFS: %w", err)
		// TODO: Handle error appropriately, maybe retry or set to recoverable state
	}

	ipfsAddTotal.WithLabelValues(metadata.Name, "success").Inc()
	logger.Infof("block added to IFPS with CID %s, publishing to IPNS beacon-name: %s, beacon-CID: %s", addResp.Cid, metadata.Name, metadata.PublicKey)

	// publish new block data to beacon key
	publishName := metadata.Name
	pubTimer := prometheus.NewTimer(ipnsPublishDuration.WithLabelValues(metadata.Name))
	_, err = ipfsPluginClient.Publish(ctx, &proto.PublishRequest{
		Cid:         addResp.Cid,
		PublishName: publishName,
	})
	pubTimer.ObserveDuration()

	if err != nil {
		ipnsPublishTotal.WithLabelValues(metadata.Name, "failed").Inc()
		return fmt.Errorf("failed to publish updated beacon block %s to IPNS beacon-name %s, beacon-CID %s: %w", addResp.Cid, metadata.Name, metadata.PublicKey, err)
	}

	ipnsPublishTotal.WithLabelValues(metadata.Name, "success").Inc()
	lastSequence.WithLabelValues(metadata.Name).Set(float64(beaconPayload.Sequence))
	lastTimestampSeconds.WithLabelValues(metadata.Name).Set(float64(beaconPayload.Timestamp))
	execTotal.WithLabelValues(metadata.Name, "success").Inc()
	logger.Infof("block %s published to beacon (%s), with CID: %s", addResp.GetCid(), publishName, metadata.PublicKey)

	return nil
}

func loadCtrngs(ctx context.Context, threads utils.ThreadControl, ctrngPluginClient proto.RandomnessPluginClient, metadata BeaconMetadata) chan []string {
	logger := utils.GetLogger("orbitport:beacon:ctrng_loader")

	resp := make(chan []string, 1)

	threads.GoCtx(ctx, func(ctx context.Context) {
		defer close(resp)

		batchSize := metadata.BatchSize
		if batchSize <= 0 {
			batchSize = 1
		}

		ctrngTimer := prometheus.NewTimer(ctrngDuration.WithLabelValues(metadata.Name))
		ctrngResp, err := ctrngPluginClient.GetTrng(ctx, &proto.TrngRequest{
			IgnoreSig: true,
			Chunks:    uint32(batchSize),
		})
		ctrngTimer.ObserveDuration()

		if err != nil {
			if ctx.Err() != nil {
				logger.Info("Context canceled while fetching CTRNGs")
				return
			}
			logger.Errorf("Failed to get cTRNGs for beacon %s: %v", metadata.Name, err)
			ctrngTotal.WithLabelValues(metadata.Name, "error").Inc()
			return
		}

		ctrngs := ctrngResp.GetValues()
		if len(ctrngs) == 0 {
			logger.Warnf("Beacon %s: Aptos returned empty values array", metadata.Name)
			return
		}
		ctrngTotal.WithLabelValues(metadata.Name, "ok").Add(float64(len(ctrngs)))

		// Non-blocking send, respect context
		select {
		case resp <- ctrngs:
		case <-ctx.Done():
			logger.Info("Context canceled before delivering CTRNGs")
			return
		}
	})

	return resp
}

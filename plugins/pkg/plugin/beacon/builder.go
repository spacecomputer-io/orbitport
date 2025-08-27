package beacon

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

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
	ctx, cancel := context.WithTimeout(c, time.Minute*2)
	defer cancel()

	logger := utils.GetLogger("orbitport:beacon:executor")

	logger.Infof("Executing beacon for metadata: %+v", metadata)

	resp := loadCtrngs(ctx, b.threads, ctrngPluginClient, metadata)
	lastCid, lastBlock, err := loadLastBeaconBlock(ctx, ipfsPluginClient, metadata.Name)
	if err != nil {
		// drain the channel
		// TODO: Handle error appropriately, maybe retry strategy or store the ctrngs for later
		select {
		case <-resp:
		default:
		}
		return fmt.Errorf("failed to load last beacon block: %v", err)
	}
	logger.Infof("Last beacon (%s) block CID: %s, Sequence: %d", metadata.Name, lastCid, lastBlock.Sequence)

	ctrngs := <-resp

	logger.Debugf("Loaded %d cTRNG values for beacon: %s", len(ctrngs), metadata.Name)

	beaconPayload := &BeaconPayload{
		Sequence:  lastBlock.Sequence + 1,
		Timestamp: time.Now().Unix(),
		CTRNG:     ctrngs,
	}

	logger.Infof("Beacon payload: %+v", beaconPayload)

	payloadBytes, err := json.Marshal(beaconPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal beacon payload: %w", err)
	}

	block := Block{
		Link: lastCid,
		Data: json.RawMessage(payloadBytes),
	}

	blockBytes, err := json.Marshal(block)
	logger.Infof("Encoded block: %s", string(blockBytes))
	if err != nil {
		return fmt.Errorf("failed to marshal beacon block: %v", err)
	}

	logger.Debugf("Beacon block JSON: %s", string(blockBytes))
	// Save block to IPFS
	addResp, err := ipfsPluginClient.Add(ctx, &proto.AddRequest{
		Data: blockBytes,
	})
	if err != nil {
		logger.Errorf("failed to add beacon block to IPFS: %v", err)
		return err
		// TODO: Handle error appropriately, maybe retry or set to recoverable state
	}

	logger.Infof("block added to IFPS with CID %s, publishing to IPNS beacon-name: %s, beacon-CID: %s", addResp.Cid, metadata.Name, metadata.PublicKey)

	// publish new block data to beacon key
	publishName := metadata.Name
	_, err = ipfsPluginClient.Publish(ctx, &proto.PublishRequest{
		Cid:         addResp.Cid,
		PublishName: publishName,
	})

	if err != nil {
		logger.Errorf("failed to publish updated beacon block %s to IPNS beacon-name %s, beacon-CID %s: %v", addResp.Cid, metadata.Name, metadata.PublicKey, err)
		return err
	}
	logger.Infof("block %s published to beacon (%s), with CID: %s", addResp.GetCid(), publishName, metadata.PublicKey)

	return nil
}

func loadCtrngs(ctx context.Context, threads utils.ThreadControl, ctrngPluginClient proto.RandomnessPluginClient, metadata BeaconMetadata) chan []string {
	logger := utils.GetLogger("orbitport:beacon:ctrng_loader")

	resp := make(chan []string, 1)

	threads.GoCtx(ctx, func(ctx context.Context) {
		defer close(resp)

		batchSize := metadata.BatchSize

		ctrngs := make([]string, 0, batchSize)

		for i := len(ctrngs); i < int(batchSize); i++ {
			ctrngResp, err := ctrngPluginClient.GetTrng(ctx, &proto.TrngRequest{
				IgnoreSig: true,
				Chunks:    1,
			})
			if err != nil {
				if ctx.Err() != nil {
					logger.Info("Context done, stopping CTRNG retrieval")
					select {
					case resp <- ctrngs:
					default:
					}
					return
				}
				logger.Errorf("Failed to get cTRNG from CTRNG plugin: %v", err)
				continue
			}
			ctrngs = append(ctrngs, ctrngResp.GetValue())
			// timeout for each CTRNG retrieval to reduce pressure on the CTRNG plugin
			select {
			case <-ctx.Done():
				logger.Info("Context done, stopping CTRNG retrieval")
				select {
				case resp <- ctrngs:
				default:
				}
				return
			case <-time.After(time.Millisecond * 100):
			}
		}

		select {
		case resp <- ctrngs:
		case <-ctx.Done():
			logger.Info("Context done, stopping CTRNG retrieval")
			return
		}
	})

	return resp
}

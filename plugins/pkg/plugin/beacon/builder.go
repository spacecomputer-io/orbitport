package beacon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	ms "github.com/spacecomputer-io/orbitport/plugins/pkg/plugin/masterseed"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	"github.com/spacecomputer-io/orbitport/plugins/proto"
)

const (
	executionTimeout      = time.Minute
	operationRetryMax     = 3
	operationRetryBackoff = time.Second
)

type beaconHead struct {
	cid   string
	block *BeaconPayload
}

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
		if cerr := ipfsConn.Close(); cerr != nil {
			logger.Errorf("error closing ipfs client connection: %v", cerr)
		}
		return fmt.Errorf("failed to connect to CTRNG plugin: %v", err)
	}

	masterConn, masterSeedClient, err := getMasterSeedPluginClient(b.cfg)
	if err != nil {
		if cerr := ipfsConn.Close(); cerr != nil {
			logger.Errorf("error closing ipfs client connection: %v", cerr)
		}
		if cerr := ctrngConn.Close(); cerr != nil {
			logger.Errorf("error closing ctrng client connection: %v", cerr)
		}
		return fmt.Errorf("failed to connect to MasterSeed plugin: %v", err)
	}

	q := b.scheduler.Queue()
	b.threads.Go(func(ctx context.Context) {
		defer func() {
			if cerr := ipfsConn.Close(); cerr != nil {
				logger.Errorf("error closing ipfs client connection: %v", cerr)
			}
			if cerr := ctrngConn.Close(); cerr != nil {
				logger.Errorf("error closing ctrng client connection: %v", cerr)
			}
			if cerr := masterConn.Close(); cerr != nil {
				logger.Errorf("error closing masterseed client connection: %v", cerr)
			}
		}()

		logger.Info("Connected to IPFS, cTRNG and MasterSeed plugins, waiting for beacon updates...")

		for {
			select {
			case <-ctx.Done():
				logger.Info("Stopping beacon execution listener")
				return
			case event, ok := <-q:
				if !ok {
					logger.Info("Beacon execution queue closed")
					return
				}

				b.threads.GoCtx(ctx, func(ctx context.Context) {
					result := b.executeBeacon(ctx, event, ctrngPluginClient, masterSeedClient, ipfsPluginClient)
					switch result.status {
					case executionStatusSuccess:
						execTotal.WithLabelValues(event.Name, "success").Inc()
					case executionStatusStale:
						execTotal.WithLabelValues(event.Name, "stale").Inc()
						if result.err != nil {
							logger.Warnf("Discarded stale beacon execution for %s: %v", event.Name, result.err)
						}
					case executionStatusRetryable:
						execTotal.WithLabelValues(event.Name, "retryable").Inc()
						if result.err != nil {
							logger.Errorf("Retryable beacon execution failure for %s: %v", event.Name, result.err)
						}
					}
					b.scheduler.completeExecution(event, result)
				})
			}
		}
	})

	return nil
}

func (b *Builder) Close() {
	logger := utils.GetLogger("orbitport:beacon:builder")
	logger.Info("Stopping beacon builder...")
	b.threads.Close()
}

func normalizeCIDRef(ref string) string {
	ref = strings.TrimSpace(ref)
	ref = strings.TrimPrefix(ref, "/ipfs/")
	ref = strings.TrimPrefix(ref, "ipfs/")
	return ref
}

func retryWithBackoff[T any](ctx context.Context, attempts int, backoff, maxDelay time.Duration, op func(context.Context) (T, error)) (T, error) {
	var zero T
	delay := backoff
	var lastErr error

	for attempt := 1; attempt <= attempts; attempt++ {
		value, err := op(ctx)
		if err == nil {
			return value, nil
		}

		lastErr = err
		if ctx.Err() != nil || attempt == attempts {
			break
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, ctx.Err()
		case <-timer.C:
		}

		if delay < maxDelay {
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}

	return zero, lastErr
}

func loadHeadWithRetry(ctx context.Context, ipfsPluginClient proto.IpfsPluginClient, beaconName string, observe bool, maxDelay time.Duration) (beaconHead, error) {
	op := func(ctx context.Context) (beaconHead, error) {
		cid, block, err := loadLastBeaconBlock(ctx, ipfsPluginClient, beaconName)
		if err != nil {
			return beaconHead{}, err
		}
		return beaconHead{cid: cid, block: block}, nil
	}

	if !observe {
		return retryWithBackoff(ctx, operationRetryMax, operationRetryBackoff, maxDelay, op)
	}

	timer := prometheus.NewTimer(loadLastDuration.WithLabelValues(beaconName))
	defer timer.ObserveDuration()

	head, err := retryWithBackoff(ctx, operationRetryMax, operationRetryBackoff, maxDelay, op)
	if err != nil {
		loadLastTotal.WithLabelValues(beaconName, "failed").Inc()
		return beaconHead{}, err
	}

	loadLastTotal.WithLabelValues(beaconName, "success").Inc()
	return head, nil
}

func addBlockWithRetry(ctx context.Context, ipfsPluginClient proto.IpfsPluginClient, beaconName string, blockBytes []byte, maxDelay time.Duration) (*proto.AddResponse, error) {
	timer := prometheus.NewTimer(ipfsAddDuration.WithLabelValues(beaconName))
	defer timer.ObserveDuration()

	resp, err := retryWithBackoff(ctx, operationRetryMax, operationRetryBackoff, maxDelay, func(ctx context.Context) (*proto.AddResponse, error) {
		return ipfsPluginClient.Add(ctx, &proto.AddRequest{Data: blockBytes})
	})
	if err != nil {
		ipfsAddTotal.WithLabelValues(beaconName, "failed").Inc()
		return nil, err
	}

	ipfsAddTotal.WithLabelValues(beaconName, "success").Inc()
	return resp, nil
}

func headMatches(head beaconHead, expectedCID string, expectedSequence uint64) bool {
	if head.block == nil {
		return false
	}
	return normalizeCIDRef(head.cid) == normalizeCIDRef(expectedCID) && head.block.Sequence == expectedSequence
}

func candidatePublished(head beaconHead, candidateCID string, candidateSequence uint64) bool {
	if head.block == nil {
		return false
	}
	return normalizeCIDRef(head.cid) == normalizeCIDRef(candidateCID) && head.block.Sequence == candidateSequence
}

func publishWithFreshHeadCheck(
	ctx context.Context,
	ipfsPluginClient proto.IpfsPluginClient,
	metadata BeaconMetadata,
	expectedHead beaconHead,
	candidateCID string,
	candidatePayload *BeaconPayload,
	maxDelay time.Duration,
) executionResult {
	timer := prometheus.NewTimer(ipnsPublishDuration.WithLabelValues(metadata.Name))
	defer timer.ObserveDuration()

	for attempt := 1; attempt <= operationRetryMax; attempt++ {
		currentHead, err := loadHeadWithRetry(ctx, ipfsPluginClient, metadata.Name, false, maxDelay)
		if err != nil {
			if attempt == operationRetryMax || ctx.Err() != nil {
				ipnsPublishTotal.WithLabelValues(metadata.Name, "failed").Inc()
				return executionResult{
					status: executionStatusRetryable,
					err:    fmt.Errorf("failed to reload current beacon head before publish: %w", err),
				}
			}
			continue
		}

		if !headMatches(currentHead, expectedHead.cid, expectedHead.block.Sequence) {
			return executionResult{
				status: executionStatusStale,
				err: fmt.Errorf(
					"beacon head changed before publish: expected cid=%s seq=%d, got cid=%s seq=%d",
					expectedHead.cid,
					expectedHead.block.Sequence,
					currentHead.cid,
					currentHead.block.Sequence,
				),
			}
		}

		_, err = ipfsPluginClient.Publish(ctx, &proto.PublishRequest{
			Cid:         candidateCID,
			PublishName: metadata.Name,
		})
		if err == nil {
			ipnsPublishTotal.WithLabelValues(metadata.Name, "success").Inc()
			return executionResult{
				status:    executionStatusSuccess,
				successAt: time.Unix(candidatePayload.Timestamp, 0),
			}
		}

		headAfterErr, headErr := loadHeadWithRetry(ctx, ipfsPluginClient, metadata.Name, false, maxDelay)
		if headErr == nil {
			if candidatePublished(headAfterErr, candidateCID, candidatePayload.Sequence) {
				ipnsPublishTotal.WithLabelValues(metadata.Name, "success").Inc()
				return executionResult{
					status:    executionStatusSuccess,
					successAt: time.Unix(candidatePayload.Timestamp, 0),
				}
			}
			if !headMatches(headAfterErr, expectedHead.cid, expectedHead.block.Sequence) {
				return executionResult{
					status: executionStatusStale,
					err: fmt.Errorf(
						"publish became stale after error: expected cid=%s seq=%d, got cid=%s seq=%d",
						expectedHead.cid,
						expectedHead.block.Sequence,
						headAfterErr.cid,
						headAfterErr.block.Sequence,
					),
				}
			}
		}

		if attempt == operationRetryMax || ctx.Err() != nil {
			ipnsPublishTotal.WithLabelValues(metadata.Name, "failed").Inc()
			return executionResult{
				status: executionStatusRetryable,
				err: fmt.Errorf(
					"failed to publish updated beacon block %s to beacon-name %s, beacon-CID %s: %w",
					candidateCID,
					metadata.Name,
					metadata.PublicKey,
					err,
				),
			}
		}

		timer := time.NewTimer(operationRetryBackoff * time.Duration(1<<(attempt-1)))
		select {
		case <-ctx.Done():
			timer.Stop()
			ipnsPublishTotal.WithLabelValues(metadata.Name, "failed").Inc()
			return executionResult{status: executionStatusRetryable, err: ctx.Err()}
		case <-timer.C:
		}
	}

	ipnsPublishTotal.WithLabelValues(metadata.Name, "failed").Inc()
	return executionResult{
		status: executionStatusRetryable,
		err:    fmt.Errorf("exhausted publish retries for beacon %s", metadata.Name),
	}
}

func (b *Builder) executeBeacon(
	c context.Context,
	metadata BeaconMetadata,
	ctrngPluginClient proto.RandomnessPluginClient,
	masterSeedClient proto.MasterSeedPluginClient,
	ipfsPluginClient proto.IpfsPluginClient,
) executionResult {
	ctx, cancel := context.WithTimeout(c, executionTimeout)
	defer cancel()

	logger := utils.GetLogger("orbitport:beacon:executor").With("beacon", metadata.Name)
	execTimer := prometheus.NewTimer(execDuration.WithLabelValues(metadata.Name))
	defer execTimer.ObserveDuration()
	maxRetryDelay := time.Duration(b.cfg.RetryMaxDelay) * time.Second

	logger.Infof("Executing beacon for metadata: %+v", metadata)

	lastHead, err := loadHeadWithRetry(ctx, ipfsPluginClient, metadata.Name, true, maxRetryDelay)
	if err != nil {
		return executionResult{
			status: executionStatusRetryable,
			err:    fmt.Errorf("failed to load last beacon block: %w", err),
		}
	}

	logger.Infof("Last beacon (%s) block CID: %s, Sequence: %d", metadata.Name, lastHead.cid, lastHead.block.Sequence)

	ctrngs, err := loadCtrngs(ctx, ctrngPluginClient, masterSeedClient, metadata)
	if err != nil {
		return executionResult{
			status: executionStatusRetryable,
			err:    err,
		}
	}

	beaconPayload := &BeaconPayload{
		Sequence:  lastHead.block.Sequence + 1,
		Timestamp: time.Now().Unix(),
		CTRNG:     ctrngs,
	}
	logger.Debugf("Beacon payload: %+v", beaconPayload)

	block := Block{
		Link: lastHead.cid,
		Data: beaconPayload,
	}

	blockBytes, err := json.Marshal(block)
	if err != nil {
		return executionResult{
			status: executionStatusRetryable,
			err:    fmt.Errorf("failed to marshal beacon block: %w", err),
		}
	}

	addResp, err := addBlockWithRetry(ctx, ipfsPluginClient, metadata.Name, blockBytes, maxRetryDelay)
	if err != nil {
		return executionResult{
			status: executionStatusRetryable,
			err:    fmt.Errorf("failed to add beacon block to IPFS: %w", err),
		}
	}

	logger.Infof(
		"Block added to IPFS with CID %s, validating current head before publish for beacon-name: %s, beacon-CID: %s",
		addResp.Cid,
		metadata.Name,
		metadata.PublicKey,
	)

	result := publishWithFreshHeadCheck(ctx, ipfsPluginClient, metadata, lastHead, addResp.Cid, beaconPayload, maxRetryDelay)
	if result.status != executionStatusSuccess {
		return result
	}

	lastSequence.WithLabelValues(metadata.Name).Set(float64(beaconPayload.Sequence))
	lastTimestampSeconds.WithLabelValues(metadata.Name).Set(float64(beaconPayload.Timestamp))
	logger.Infof("Block %s published to beacon (%s), with CID: %s", addResp.GetCid(), metadata.Name, metadata.PublicKey)

	return result
}

func loadCtrngs(
	ctx context.Context,
	ctrngPluginClient proto.RandomnessPluginClient,
	masterSeedClient proto.MasterSeedPluginClient,
	metadata BeaconMetadata,
) ([]string, error) {
	logger := utils.GetLogger("orbitport:beacon:ctrng_loader")

	batchSize := metadata.BatchSize
	if batchSize <= 0 {
		batchSize = 1
	}

	var ctrngSeed string

	ctrngTimer := prometheus.NewTimer(ctrngDuration.WithLabelValues(metadata.Name))
	ctrngResp, err := ctrngPluginClient.GetTrng(ctx, &proto.TrngRequest{
		IgnoreSig: true,
		Chunks:    1,
	})
	ctrngTimer.ObserveDuration()

	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		logger.Errorf("Failed to get cTRNGs from aptos orbital for beacon %s: %v", metadata.Name, err)
		ctrngTotal.WithLabelValues(metadata.Name, "error").Inc()
	}

	if ctrngResp != nil {
		values := ctrngResp.GetValues()
		if len(values) > 0 {
			ctrngSeed = values[0]
		}
	}

	if ctrngSeed != "" {
		logger.Infof("Beacon %s: using CTRNG to seed MasterSeed plugin", metadata.Name)

		ctrngs, err := ms.DeriveBulkFromSeedHex(ctrngSeed, int(batchSize))
		if err != nil {
			logger.Errorf("Failed to derive TRNGs from cTRNG via MasterSeed plugin for beacon %s: %v", metadata.Name, err)
			ctrngTotal.WithLabelValues(metadata.Name, "error_ms_seeded_local").Inc()
			return nil, fmt.Errorf("failed to derive TRNGs from cTRNG for beacon %s: %w", metadata.Name, err)
		}

		if len(ctrngs) == 0 {
			logger.Warnf("Beacon %s: local MasterSeed derivation returned no values for CTRNG-seeded request", metadata.Name)
			return nil, fmt.Errorf("no CTRNG values derived for beacon %s", metadata.Name)
		}

		ctrngTotal.WithLabelValues(metadata.Name, "ok").Add(float64(len(ctrngs)))
		return ctrngs, nil
	}

	logger.Warnf("Beacon %s: no CTRNG available, falling back to MasterSeed plugin only", metadata.Name)

	msResp, msErr := masterSeedClient.GetSeeds(ctx, &proto.GetSeedsRequest{
		Count: uint32(batchSize),
	})
	if msErr != nil {
		logger.Errorf("Failed to fetch RNGs from MasterSeed plugin for beacon %s: %v", metadata.Name, msErr)
		ctrngTotal.WithLabelValues(metadata.Name, "error_ms_fallback").Inc()
		return nil, fmt.Errorf("failed to fetch RNGs from MasterSeed plugin for beacon %s: %w", metadata.Name, msErr)
	}

	ctrngs := msResp.GetValues()
	if len(ctrngs) == 0 {
		logger.Warnf("Beacon %s: MasterSeed plugin returned no values in fallback path", metadata.Name)
		return nil, fmt.Errorf("masterseed fallback returned no values for beacon %s", metadata.Name)
	}

	ctrngTotal.WithLabelValues(metadata.Name, "fallback").Add(float64(len(ctrngs)))
	return ctrngs, nil
}

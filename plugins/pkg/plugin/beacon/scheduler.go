package beacon

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/spacecomputerio/orbitport/plugins/pkg/utils"
)

type Scheduler struct {
	threads utils.ThreadControl
	cfg     Config

	registry *Registry

	q chan BeaconMetadata // channel to hold beacon update/exec events

	lastExecs map[string]time.Time
	lock      sync.RWMutex
}

// NewScheduler creates a new Scheduler instance for managing beacon execution.
func NewScheduler(cfg Config, registry *Registry) *Scheduler {
	return &Scheduler{
		threads:   utils.NewThreadControl(),
		cfg:       cfg,
		registry:  registry,
		q:         make(chan BeaconMetadata, 16),
		lastExecs: make(map[string]time.Time),
	}
}

// Start starts the scheduler, which will periodically update the last execution times of beacons.
func (s *Scheduler) Start(ctx context.Context) error {
	logger := utils.GetLogger("orbitport:beacon:scheduler")
	logger.Info("Starting beacon scheduler...")

	// Update last execution times at startup
	if err := s.updateLastExecs(ctx); err != nil {
		return fmt.Errorf("failed to update last execution times: %w", err)
	}

	// Start a background thread to periodically update last execution times
	s.threads.Go(func(ctx context.Context) {
		ticker := time.NewTicker(10 * time.Second) // Adjust the interval as needed
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.checkAndTriggerBeacons()
			}
		}
	})

	return nil
}

// Close stops the scheduler and any background tasks it has started.
func (s *Scheduler) Close() error {
	logger := utils.GetLogger("orbitport:beacon:scheduler")
	logger.Info("Stopping beacon scheduler...")

	// Stop all background threads
	s.threads.Close()
	close(s.q)

	return nil
}

// Queue returns a channel that can be used to receive beacon metadata for processing.
func (s *Scheduler) Queue() <-chan BeaconMetadata {
	return s.q
}

// checkAndTriggerBeacons is called periodically to check if any beacons need to be executed based on their cron schedules.
// It updates the last execution times and queues beacons for processing.
// This function is thread-safe and uses a mutex to protect access to shared state.
func (s *Scheduler) checkAndTriggerBeacons() {
	s.lock.Lock()
	defer s.lock.Unlock()

	logger := utils.GetLogger("orbitport:beacon:scheduler")

	for _, beacon := range s.registry.Beacons {
		if beacon.Interval == 0 {
			continue // Skip beacons without a cron schedule
		}
		// Check if the beacon needs to be updated based on its cron schedule
		if lastExec, exists := s.lastExecs[beacon.Name]; exists {
			if time.Since(lastExec) < beacon.Interval {
				continue // Skip if the beacon was recently updated
			}
		}

		// Add the beacon to the queue for processing
		logger.Infof("Scheduling beacon execution for: %s", beacon.Name)
		select {
		case s.q <- beacon:
			logger.Debugf("Beacon execution queued for: %s", beacon.Name)
			s.lastExecs[beacon.Name] = time.Now() // Update last execution time
		default:
			logger.Warnf("Beacon queue is full, skipping execution for: %s", beacon.Name)
			// TODO: Handle the case where the queue is full
			// This could involve logging, retrying later, or dropping the beacon
			continue
		}
	}
}

func (s *Scheduler) updateLastExecs(ctx context.Context) error {
	logger := utils.GetLogger("orbitport:beacon:scheduler")

	conn, ipfsPluginClient, err := getIpfsPluginClient(s.cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to IPFS plugin: %v", err)
	}
	defer func() {
		err := conn.Close()
		if err != nil {
			logger.Errorf("error closing ipfs plugin connection: %v", err)
		}
	}()

	for _, beacon := range s.registry.Beacons {
		_, lastBlock, err := loadLastBeaconBlock(ctx, ipfsPluginClient, beacon.Name)
		if err != nil {
			logger.Errorf("Failed to load last beacon block for %s: %v", beacon.Name, err)
			continue // Skip this beacon if we can't load its last block
		}
		logger.Infof("lastBlock fetched %v\n", lastBlock)
		s.setLastExec(beacon.Name, time.Unix(lastBlock.Timestamp, 0))
	}
	return nil
}

func (s *Scheduler) setLastExec(beacon string, t time.Time) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.lastExecs[beacon] = t
}

package beacon

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/core/health"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
)

type executionStatus string

const (
	executionStatusSuccess   executionStatus = "success"
	executionStatusRetryable executionStatus = "retryable"
	executionStatusStale     executionStatus = "stale"
)

type executionResult struct {
	status    executionStatus
	err       error
	successAt time.Time
}

type beaconRunState struct {
	inFlight            bool
	lastSuccess         time.Time
	retryAfter          time.Time
	consecutiveFailures uint32
	lastError           string
}

type Scheduler struct {
	threads utils.ThreadControl
	cfg     Config

	registry *Registry

	q chan BeaconMetadata // channel to hold beacon update/exec events

	states map[string]*beaconRunState
	lock   sync.RWMutex
}

// NewScheduler creates a new Scheduler instance for managing beacon execution.
func NewScheduler(cfg Config, registry *Registry) *Scheduler {
	s := &Scheduler{
		threads:  utils.NewThreadControl(),
		cfg:      cfg,
		registry: registry,
		q:        make(chan BeaconMetadata, 16),
		states:   make(map[string]*beaconRunState),
	}

	// Register gauge, closure captures s.q, queueDepth is scaped automatically by prometheus (less stressful than manually setting value)
	RegisterQueueDepthGauge(func() float64 {
		return float64(len(s.q))
	})

	return s
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
		ticker := time.NewTicker(time.Duration(s.cfg.SchedulerTickInterval) * time.Second)
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
func (s *Scheduler) Close() {
	logger := utils.GetLogger("orbitport:beacon:scheduler")
	logger.Info("Stopping beacon scheduler...")

	// Stop all background threads
	s.threads.Close()
	close(s.q)
}

// Queue returns a channel that can be used to receive beacon metadata for processing.
func (s *Scheduler) Queue() <-chan BeaconMetadata {
	return s.q
}

func (s *Scheduler) stateLocked(name string) *beaconRunState {
	if st, ok := s.states[name]; ok {
		return st
	}

	st := &beaconRunState{}
	s.states[name] = st
	beaconInFlight.WithLabelValues(name).Set(0)
	consecutiveFailures.WithLabelValues(name).Set(0)
	lastSuccessTimestampSeconds.WithLabelValues(name).Set(0)
	retryAfterTimestampSeconds.WithLabelValues(name).Set(0)
	return st
}

func backoffDelay(baseDelay, maxDelay time.Duration, failures uint32) time.Duration {
	if failures == 0 {
		return baseDelay
	}

	delay := baseDelay
	for i := uint32(1); i < failures; i++ {
		delay *= 2
		if delay >= maxDelay {
			return maxDelay
		}
	}
	if delay > maxDelay {
		return maxDelay
	}
	return delay
}

func (s *Scheduler) noteSuccessLocked(name string, ts time.Time) {
	st := s.stateLocked(name)
	st.lastSuccess = ts
	st.retryAfter = time.Time{}
	st.consecutiveFailures = 0
	st.lastError = ""
	lastSuccessTimestampSeconds.WithLabelValues(name).Set(float64(ts.Unix()))
	retryAfterTimestampSeconds.WithLabelValues(name).Set(0)
	consecutiveFailures.WithLabelValues(name).Set(0)
}

func (s *Scheduler) completeExecution(metadata BeaconMetadata, result executionResult) {
	s.lock.Lock()
	defer s.lock.Unlock()

	now := time.Now()
	st := s.stateLocked(metadata.Name)
	st.inFlight = false
	beaconInFlight.WithLabelValues(metadata.Name).Set(0)

	switch result.status {
	case executionStatusSuccess:
		ts := result.successAt
		if ts.IsZero() {
			ts = now
		}
		s.noteSuccessLocked(metadata.Name, ts)
	case executionStatusStale:
		st.retryAfter = now.Add(time.Duration(s.cfg.StaleRetryDelay) * time.Second)
		st.lastError = ""
		retryAfterTimestampSeconds.WithLabelValues(metadata.Name).Set(float64(st.retryAfter.Unix()))
		retryScheduledTotal.WithLabelValues(metadata.Name, "stale").Inc()
		staleAttemptTotal.WithLabelValues(metadata.Name).Inc()
	case executionStatusRetryable:
		st.consecutiveFailures++
		st.lastError = ""
		if result.err != nil {
			st.lastError = result.err.Error()
		}
		delay := backoffDelay(
			time.Duration(s.cfg.RetryBaseDelay)*time.Second,
			time.Duration(s.cfg.RetryMaxDelay)*time.Second,
			st.consecutiveFailures,
		)
		st.retryAfter = now.Add(delay)
		consecutiveFailures.WithLabelValues(metadata.Name).Set(float64(st.consecutiveFailures))
		retryAfterTimestampSeconds.WithLabelValues(metadata.Name).Set(float64(st.retryAfter.Unix()))
		retryScheduledTotal.WithLabelValues(metadata.Name, "retryable").Inc()
	}
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func (s *Scheduler) HealthCheck(_ context.Context) (health.HealthState, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	now := time.Now()
	for _, beacon := range s.registry.Beacons {
		st, ok := s.states[beacon.Name]
		if !ok {
			continue
		}

		if st.consecutiveFailures < s.cfg.HealthFailureThreshold {
			continue
		}

		grace := maxDuration(beacon.Interval*2, 30*time.Second)
		if st.lastSuccess.IsZero() || now.Sub(st.lastSuccess) > grace {
			errMsg := st.lastError
			if errMsg == "" {
				errMsg = "repeated execution failures"
			}
			return health.HealthStateUnhealthy, fmt.Errorf("beacon %s unhealthy: %s", beacon.Name, errMsg)
		}
	}

	return health.HealthStateHealthy, nil
}

// checkAndTriggerBeacons is called periodically to check if any beacons need to be executed based on their cron schedules.
// It queues beacons for processing when they are due or when a retry becomes eligible.
// This function is thread-safe and uses a mutex to protect access to shared state.
func (s *Scheduler) checkAndTriggerBeacons() {
	s.lock.Lock()
	defer s.lock.Unlock()

	schedTickTotal.Inc()
	logger := utils.GetLogger("orbitport:beacon:scheduler")
	now := time.Now()

	for _, beacon := range s.registry.Beacons {
		st := s.stateLocked(beacon.Name)
		if beacon.Interval == 0 {
			skippedTotal.WithLabelValues(beacon.Name, "no_interval").Inc()
			continue // Skip beacons without a cron schedule
		}

		if st.inFlight {
			skippedTotal.WithLabelValues(beacon.Name, "in_flight").Inc()
			continue
		}

		if !st.retryAfter.IsZero() {
			if now.Before(st.retryAfter) {
				skippedTotal.WithLabelValues(beacon.Name, "retry_backoff").Inc()
				continue
			}
		} else if !st.lastSuccess.IsZero() {
			if now.Sub(st.lastSuccess) < beacon.Interval {
				skippedTotal.WithLabelValues(beacon.Name, "too_recent").Inc()
				continue // Skip if the beacon was recently updated
			}
		}

		logger.Infof("Scheduling beacon execution for: %s, with interval: %v", beacon.Name, beacon.Interval)
		select {
		case s.q <- beacon:
			logger.Debugf("Beacon execution queued for: %s", beacon.Name)
			st.inFlight = true
			st.retryAfter = time.Time{}
			beaconInFlight.WithLabelValues(beacon.Name).Set(1)
			retryAfterTimestampSeconds.WithLabelValues(beacon.Name).Set(0)
			scheduledExecutionsTotal.WithLabelValues(beacon.Name).Inc()
		default:
			logger.Warnf("Beacon queue is full, skipping execution for: %s", beacon.Name)
			skippedTotal.WithLabelValues(beacon.Name, "queue_full").Inc()
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
		s.setLastSuccess(beacon.Name, time.Unix(lastBlock.Timestamp, 0))
	}
	return nil
}

func (s *Scheduler) setLastSuccess(beacon string, t time.Time) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.noteSuccessLocked(beacon, t)
}

package beacon

import (
	"context"
	"testing"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/core/health"
)

func testBeacon(name string, interval time.Duration) BeaconMetadata {
	return BeaconMetadata{
		Name:      name,
		PublicKey: "pubkey",
		Version:   "1.0",
		Encoding:  "json",
		BatchSize: 1,
		Message:   "msg",
		Interval:  interval,
	}
}

func testSchedulerConfig() Config {
	return Config{
		SchedulerTickInterval:  1,
		RetryBaseDelay:         2,
		RetryMaxDelay:          60,
		StaleRetryDelay:        2,
		HealthFailureThreshold: 3,
	}
}

func TestSchedulerSuccessUpdatesLastSuccess(t *testing.T) {
	s := NewScheduler(testSchedulerConfig(), &Registry{
		Beacons: []BeaconMetadata{testBeacon("alpha", 10*time.Second)},
	})

	s.checkAndTriggerBeacons()

	select {
	case <-s.Queue():
	default:
		t.Fatal("expected beacon to be queued")
	}

	s.completeExecution(BeaconMetadata{Name: "alpha"}, executionResult{
		status:    executionStatusSuccess,
		successAt: time.Now(),
	})

	state := s.states["alpha"]
	if state == nil {
		t.Fatal("expected scheduler state to exist")
	}
	if state.inFlight {
		t.Fatal("expected in-flight state to be cleared after success")
	}
	if state.lastSuccess.IsZero() {
		t.Fatalf("expected last success to be updated, got %v", state.lastSuccess)
	}
	if state.consecutiveFailures != 0 {
		t.Fatalf("expected consecutive failures to be reset, got %d", state.consecutiveFailures)
	}

	s.checkAndTriggerBeacons()
	select {
	case <-s.Queue():
		t.Fatal("did not expect beacon to be re-queued immediately after success")
	default:
	}
}

func TestSchedulerRetryableFailureBacksOff(t *testing.T) {
	s := NewScheduler(testSchedulerConfig(), &Registry{
		Beacons: []BeaconMetadata{testBeacon("beta", 10*time.Second)},
	})

	s.checkAndTriggerBeacons()
	select {
	case <-s.Queue():
	default:
		t.Fatal("expected beacon to be queued")
	}

	s.completeExecution(BeaconMetadata{Name: "beta"}, executionResult{
		status: executionStatusRetryable,
		err:    context.DeadlineExceeded,
	})

	state := s.states["beta"]
	if state == nil {
		t.Fatal("expected scheduler state to exist")
	}
	if state.inFlight {
		t.Fatal("expected in-flight state to be cleared after retryable failure")
	}
	if state.consecutiveFailures != 1 {
		t.Fatalf("expected consecutive failures to be incremented, got %d", state.consecutiveFailures)
	}
	if state.retryAfter.IsZero() {
		t.Fatal("expected retryAfter to be scheduled")
	}

	s.checkAndTriggerBeacons()
	select {
	case <-s.Queue():
		t.Fatal("did not expect beacon to be queued before retryAfter")
	default:
	}

	s.lock.Lock()
	state.retryAfter = time.Now().Add(-time.Second)
	s.lock.Unlock()

	s.checkAndTriggerBeacons()
	select {
	case <-s.Queue():
	default:
		t.Fatal("expected beacon to be re-queued after retryAfter elapsed")
	}
}

func TestSchedulerHealthCheckFailsAfterRepeatedFailures(t *testing.T) {
	s := NewScheduler(testSchedulerConfig(), &Registry{
		Beacons: []BeaconMetadata{testBeacon("gamma", 5*time.Second)},
	})

	s.lock.Lock()
	state := s.stateLocked("gamma")
	state.consecutiveFailures = 3
	state.lastError = "publish failed repeatedly"
	s.lock.Unlock()

	hs, err := s.HealthCheck(context.Background())
	if hs != health.HealthStateUnhealthy {
		t.Fatalf("expected unhealthy health state, got %v", hs)
	}
	if err == nil {
		t.Fatal("expected health check error for repeated failures")
	}
}

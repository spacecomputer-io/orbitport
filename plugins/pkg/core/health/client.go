package health

import (
	"context"
	"fmt"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func WaitForDependencies(ctx context.Context, retryDelay time.Duration, maxDelay time.Duration, dependencies ...string) error {
	logger := utils.GetLogger("orbitport:health")
	startTime := time.Now()

	remaining := make(map[string]struct{})
	for _, addr := range dependencies {
		remaining[addr] = struct{}{}
	}

	for {
		// Collect which dependencies are still unhealthy in this iteration
		var toRemove []string

		for addr := range remaining {
			if checkDepHealth(ctx, addr) {
				toRemove = append(toRemove, addr)
			}
		}

		// Remove healthy dependencies
		for _, addr := range toRemove {
			delete(remaining, addr)
		}

		if len(remaining) == 0 {
			logger.Infof("All dependencies are healthy. Time elapsed: %s\n", time.Since(startTime))
			return nil
		}

		logger.Infof("Not all dependencies are healthy (remaining: %v). Time elapsed: %s. Retrying in %s\n",
			remaining, time.Since(startTime), retryDelay)

		select {
		case <-time.After(retryDelay):
			retryDelay *= 2
			if retryDelay > maxDelay {
				retryDelay = maxDelay
			}
		case <-ctx.Done():
			return fmt.Errorf("retry canceled for timeout: %w", ctx.Err())
		}
	}
}

func checkDepHealth(ctx context.Context, addr string) bool {
	logger := utils.GetLogger("orbitport:health")
	if err := Check(ctx, addr); err != nil {
		logger.Infof("Dependency %s is not healthy: %v", addr, err)
		return false
	}

	logger.Infof("Dependency %s is healthy!", addr)
	return true
}

// Check returns nil when the gRPC health service at addr reports SERVING.
func Check(ctx context.Context, addr string) error {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close() }()

	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		return fmt.Errorf("health check RPC: %w", err)
	}
	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		return fmt.Errorf("status %s", resp.GetStatus())
	}
	return nil
}

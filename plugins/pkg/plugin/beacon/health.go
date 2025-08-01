package beacon

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/spacecomputerio/orbitport/plugins/pkg/core/health"
)

func IpfsHealthCheck(ctx context.Context) (health.HealthState, error) {
	cfg := readFromEnv()
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(cfg.IPFSAddress + "/api/v0/version")
	if err != nil {
		return health.HealthStateUnhealthy, fmt.Errorf("IPFS not reachable: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return health.HealthStateUnhealthy, fmt.Errorf("IPFS API error: %s", resp.Status)
	}
	return health.HealthStateHealthy, nil
}

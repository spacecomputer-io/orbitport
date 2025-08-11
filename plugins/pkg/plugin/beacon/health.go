package beacon

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/core/health"
)

func IpfsHealthCheck(ctx context.Context) (health.HealthState, error) {
	cfg := readFromEnv() // shohuld resolve to IPFSAddress used by ipfs plugin
	client := &http.Client{Timeout: 2 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.IPFSAddress+"/api/v0/version", nil)
	if err != nil {
		return health.HealthStateUnhealthy, fmt.Errorf("build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return health.HealthStateUnhealthy, fmt.Errorf("IPFS not reachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return health.HealthStateUnhealthy, fmt.Errorf("IPFS API error: %s", resp.Status)
	}
	return health.HealthStateHealthy, nil
}

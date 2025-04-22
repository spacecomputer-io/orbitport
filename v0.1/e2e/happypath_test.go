package integrationtests

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/spacecomputerio/orbitport/internal/api/auth"
	randomness_common "github.com/spacecomputerio/orbitport/internal/randomness/common"
)

/// Run with:
/// cp -r ./bin ./e2e/bin
/// go test -v ./e2e/...

func TestE2E(t *testing.T) {
	go startOrbitport()
	fmt.Println("Orbitport started")
	for {
		if _, err := curlMetrics(); err != nil {
			fmt.Println("Waiting for Orbitport to start...")
			time.Sleep(1 * time.Second)
			continue
		}
		break
	}
	fmt.Println("Orbitport is ready")
	<-time.After(2 * time.Second)

	token, err := getAccessToken()
	require.NoError(t, err)
	fmt.Printf("Access token: %s\n", token)
	seed, err := randSeedRequest(token)
	require.NoError(t, err)
	fmt.Printf("Random seed: %+v", seed)
	<-time.After(2 * time.Second)

	lines, err := curlMetrics()
	require.NoError(t, err)
	fmt.Printf("Metrics: %s\n", lines)
}

func startOrbitport() {
	err := exec.Command("./bin/gateway").Run()
	if err != nil {
		fmt.Println("Error starting Orbitport:", err)
	}
	fmt.Println("Orbitport stopped")
}

func curlMetrics() ([]byte, error) {
	cmd := exec.Command("curl", "http://localhost:8081/metrics")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}

func randSeedRequest(token string) (*randomness_common.RandomSeed, error) {
	cmd := exec.Command("curl", "--request", "GET", "--url", "http://localhost:8080/v1/rand_seed", "--header", fmt.Sprintf("Authorization: Bearer %s", token))
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	fmt.Printf("Rand seed response: %s\n", out)
	var seed randomness_common.RandomSeed
	if err := json.Unmarshal(out, &seed); err != nil {
		return nil, err
	}
	return &seed, nil
}

func getAccessToken() (string, error) {
	c := auth.NewAuthClient("4DBFFgOjgd76yFBjC8qeftDfUcve4RZN", "vzKlpleNyCkifmgW5BHI6uS-qHetXMOh64auo34X3ReyiBODWEeXgzdohwGliK-K", "https://dev-1usujmbby8627ni8.us.auth0.com/oauth/token")
	token, err := c.GetAccessToken(context.Background())
	if err != nil {
		return "", err
	}
	return token.Value, nil
}

package aptosorbital

import (
	"context"
	"fmt"

	"github.com/spacecomputerio/orbitport/agents/pkg/utils"
	"github.com/spacecomputerio/orbitport/agents/proto"
)

// Agent implements the interfaces for the Aptos Orbital API.
type Agent struct {
	proto.RandomnessAgentServer

	aptosClient *AptosClient
}

// NewAgent creates a new Aptos Orbital agent.
func NewAgent() (*Agent, error) {
	cfg := readFromEnv()

	logger := utils.GetLogger("orbitport:aptosorbital")
	logger.Infof("creating agent with API url=%s, auth url=%s, client id=%s",
		cfg.AptosOrbitalApiUrl,
		cfg.AptosOrbitalAuthUrl,
		cfg.AptosOrbitalClientId,
	)

	aptosClient, err := NewClient(
		WithApiURL(cfg.AptosOrbitalApiUrl),
		WithAuthURL(cfg.AptosOrbitalAuthUrl),
		WithClientID(cfg.AptosOrbitalClientId),
		WithClientSecret(cfg.AptosOrbitalClientSecret),
		WithRateLimit(float64(cfg.AptosOrbitalRateLimit), 2),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Aptos Orbital client: %w", err)
	}

	return &Agent{
		aptosClient: aptosClient,
	}, nil
}

// GetTrng handles the GetTrng RPC call.
// It retrieves a true randomness seed from the Aptos Orbital API.
// The request contains the number of chunks to retrieve and whether to ignore the signature.
func (a *Agent) GetTrng(ctx context.Context, req *proto.TrngRequest) (*proto.TrngResponse, error) {
	numChunk := uint(req.Chunks)
	// defaults to 1 if numChunk is 0
	if numChunk == 0 {
		numChunk = 1
	}
	return a.aptosClient.GetTrueRandomnessSeed(ctx, req.IgnoreSig, numChunk)
}

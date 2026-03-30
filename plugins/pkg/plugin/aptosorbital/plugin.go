package aptosorbital

import (
	"context"
	"errors"
	"fmt"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	"github.com/spacecomputer-io/orbitport/plugins/proto"
)

// Plugin implements the interfaces for the Aptos Orbital API.
type Plugin struct {
	proto.RandomnessPluginServer

	aptosClient *AptosClient
}

// NewPlugin creates a new Aptos Orbital plugin.
func NewPlugin() (*Plugin, error) {
	cfg := readFromEnv()

	logger := utils.GetLogger("orbitport:aptosorbital")
	logger.Infof("creating plugin with API url=%s, auth url=%s, client id=%s",
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

	return &Plugin{
		aptosClient: aptosClient,
	}, nil
}

// GetTrng handles the GetTrng RPC call.
// It retrieves a true randomness seed from the Aptos Orbital API.
// The request contains the number of chunks to retrieve and whether to ignore the signature.
func (p *Plugin) GetTrng(ctx context.Context, req *proto.TrngRequest) (*proto.TrngResponse, error) {
	logger := utils.GetLogger("orbitport:aptosorbital:gettrng")
	numChunk := int(req.Chunks)
	if numChunk == 0 {
		numChunk = 1
	}

	// Try Aptos Orbital for fresh randomness
	resp, err := p.aptosClient.GetTrueRandomnessSeed(ctx, req.IgnoreSig, uint(numChunk))
	if err == nil && resp != nil && len(resp.GetValues()) > 0 {
		return resp, nil
	}

	if errors.Is(err, ErrNoDataAvailable) {
		logger.Infof("Aptos has no fresh randomness available, falling back to master seeds")
		return &proto.TrngResponse{Values: []string{}, Sig: ""}, nil
	}

	if err != nil {
		logger.Warnf("Aptos failed to deliver fresh rng: %v", err)
		return nil, err
	}

	logger.Infof("Aptos returned no fresh randomness, falling back to master seeds")

	// Return empty values facilitating a fallback to MasterSeed
	return &proto.TrngResponse{Values: []string{}, Sig: ""}, nil
}

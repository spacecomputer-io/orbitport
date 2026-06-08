package crypto2

import (
	"context"
	"fmt"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

// Plugin implements the interfaces for the Crypto2 API.
type Plugin struct {
	proto.RandomnessPluginServer

	client *Client
}

// NewPlugin creates a new Crypto2 plugin.
func NewPlugin() (*Plugin, error) {
	cfg := readFromEnv()

	logger := utils.GetLogger("orbitport:crypto2")
	logger.Infof("creating plugin with API url=%s, auth url=%s, client id=%s",
		cfg.APIURL,
		cfg.AuthURL,
		cfg.ClientID,
	)

	client, err := NewClient(
		WithApiURL(cfg.APIURL),
		WithAuthURL(cfg.AuthURL),
		WithClientID(cfg.ClientID),
		WithClientSecret(cfg.ClientSecret),
		WithRateLimit(float64(cfg.RateLimit), 2),
		WithTimeout(time.Duration(cfg.Timeout)*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Crypto2 client: %w", err)
	}

	return &Plugin{
		client: client,
	}, nil
}

// GetTrng handles the GetTrng RPC call.
// It retrieves a true randomness seed from the Crypto2 API.
// The request contains the number of chunks to retrieve and whether to ignore the signature.
func (p *Plugin) GetTrng(ctx context.Context, req *proto.TrngRequest) (*proto.TrngResponse, error) {
	logger := utils.GetLogger("orbitport:crypto2:gettrng")
	numChunk := int(req.Chunks)
	if numChunk == 0 {
		numChunk = 1
	}

	// Try Crypto2 for fresh randomness
	resp, err := p.client.GetTrueRandomnessSeed(ctx, req.IgnoreSig, uint(numChunk))
	if err == nil && resp != nil && len(resp.GetValues()) > 0 {
		return resp, nil
	}

	// Crypto2 failed or returned no values
	logger.Warnf("Crypto2 failed to deliver fresh RNG, falling back to master seeds: %v", err)

	// Return empty values facilitating a fallback to MasterSeed
	return &proto.TrngResponse{Values: []string{}, Sig: ""}, nil
}

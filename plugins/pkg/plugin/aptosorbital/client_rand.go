package aptosorbital

import (
	"context"
	"encoding/hex"
	"fmt"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

// trngSeedResponse is a wrapper for the response of the trng_seed endpoint, which is an array of trngSeed.
type trngSeedResponse = []trngSeed

// trngSeed represents the response for the trng_seed endpoint.
type trngSeed struct {
	Chunk     string `json:"chunk"`
	Signature string `json:"signature"`
}

// GetTrueRandomnessSeed retrieves a true randomness seed from the Aptos Orbital API.
func (c *AptosClient) GetTrueRandomnessSeed(ctx context.Context, noSig bool, numChunk uint) (*proto.TrngResponse, error) {
	if !c.limiter.Allow() {
		c.logger.Warn("rate limit exceeded")
		requestTotal.WithLabelValues("local_rate_limit_exceeded").Inc()
		return nil, ErrRateLimitExceeded
	}

	headers, err := c.getHeaders(ctx)
	if err != nil {
		return nil, err
	}
	noSigInt := 0
	if noSig {
		noSigInt = 1
	}
	urlStr := fmt.Sprintf("%s/services/v1/trng_seed?no_sig=%d&num_chunk=%d", c.opts.apiURL, noSigInt, numChunk)

	resp, err := makeRequest[trngSeedResponse](ctx, c, "GET", urlStr, headers, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make trng_seed request: %w", err)
	}
	if resp == nil || len(*resp) == 0 {
		return nil, fmt.Errorf("empty response from trng_seed")
	}

	// Collect all chunks
	values := make([]string, 0, len(*resp))
	byteCount := 0
	var sig string
	for i, r := range *resp {
		if i == 0 {
			sig = r.Signature
		}
		values = append(values, r.Chunk)
		byteCount += hex.DecodedLen(len(r.Chunk))
	}

	trngChunksTotal.Add(float64(len(values)))
	trngBytesTotal.Add(float64(byteCount))
	trngChunksPerRequest.Observe(float64(len(values)))

	return &proto.TrngResponse{
		Values: values,
		Sig:    sig,
	}, nil
}

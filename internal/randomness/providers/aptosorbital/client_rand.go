package aptosorbital

import (
	"fmt"

	randomness_common "github.com/spacecoinxyz/stargate/internal/randomness/common"
)

// trngSeedResponse represents the response for the trng_seed endpoint.
type trngSeedResponse struct {
	Chunk     string `json:"chunk"`
	Signature string `json:"signature"`
}

func (r *trngSeedResponse) toRandomSeed() randomness_common.RandomSeed {
	return randomness_common.RandomSeed{
		Value: r.Chunk,
		Sig:   r.Signature,
	}
}

// GetTrueRandomnessSeed retrieves a true randomness seed from the Aptos Orbital API.
func (c *AptosClient) GetTrueRandomnessSeed(noSig bool, numChunk uint) (*randomness_common.RandomSeed, error) {
	if !c.limiter.Allow() {
		c.logger.Warn("rate limit exceeded")
		// TODO: think about how to handle rate limit exceeded.
		// currently the rate limiting is applied to the entire service
		// as we don't distinguish between different callers
		return nil, ErrRateLimitExceeded
	}

	headers, err := c.getHeaders()
	if err != nil {
		return nil, err
	}
	noSigInt := 0
	if noSig {
		noSigInt = 1
	}
	urlStr := fmt.Sprintf("%s/services/v1/trng_seed?no_sig=%d&num_chunk=%d", c.opts.apiURL, noSigInt, numChunk)
	resp, err := makeRequest[trngSeedResponse](c, "GET", urlStr, headers, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make trng_seed request: %v", err)
	}
	result := resp.toRandomSeed()

	return &result, nil
}

package aptosorbital

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spacecoinxyz/orbitport/agents/pkg/oauth"
	"github.com/spacecoinxyz/orbitport/agents/pkg/utils"
	"golang.org/x/time/rate"
)

var (
	ErrDailyRateLimitExceeded = fmt.Errorf("aptos orbial daily rate limit exceeded")
	ErrRateLimitExceeded      = fmt.Errorf("rate limit exceeded")
)

// AptosClient is a client for the Aptos Orbital API.
type AptosClient struct {
	logger     *utils.Logger
	opts       *ClientOptions
	limiter    *rate.Limiter
	authClient *oauth.OAuthClient
}

// NewClient creates a new AptosClient with the given options.
func NewClient(opts ...ClientOption) (*AptosClient, error) {
	o := &ClientOptions{}
	if err := o.apply(opts...); err != nil {
		return nil, err
	}

	limiter := rate.NewLimiter(rate.Limit(o.rateLimit), o.rateBurst)

	logger := utils.GetLogger("orbitport:randomness:aptosorbital")

	return &AptosClient{
		logger:     logger,
		opts:       o,
		limiter:    limiter,
		authClient: oauth.NewOAuthClient(o.clientID, o.clientSecret, o.authURL),
	}, nil
}

// getHeaders retrieves the headers for making a request.
func (c *AptosClient) getHeaders(ctx context.Context) (map[string]string, error) {
	atoken, err := c.authClient.GetAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %v", err)
	}
	return map[string]string{
		"Authorization": "Bearer " + atoken.Value,
	}, nil
}

// makeRequest makes a request according to the given parameters.
// This is a generic function that takes a type R which represents the Response.
// TODO: manage request data properly.
func makeRequest[R any](ctx context.Context, c *AptosClient, method, urlStr string, headers map[string]string, data interface{}, params map[string]string) (*R, error) {
	if params != nil {
		query := url.Values{}
		for key, value := range params {
			query.Set(key, value)
		}
		urlStr += "?" + query.Encode()
	}

	var body []byte
	if data != nil {
		var err error
		body, err = json.Marshal(data)
		if err != nil {
			return nil, err
		}
	}

	requestTotal.WithLabelValues("sent").Inc()
	c.logger.Debugf("making %s request to %s", method, urlStr)

	timer := prometheus.NewTimer(requestDuration)
	defer timer.ObserveDuration()

	req, err := http.NewRequestWithContext(ctx, method, urlStr, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if data != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{
		Timeout: c.opts.timeout,
	}
	resp, err := client.Do(req)
	if err != nil {
		requestTotal.WithLabelValues("failed").Inc()
		return nil, fmt.Errorf("failed to reach end-point: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			c.logger.Warnf("failed to close response body: %v", err)
		}
	}()

	// TODO: handle response status codes properly.
	if resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusAccepted {
		if resp.StatusCode == http.StatusBadRequest {
			requestTotal.WithLabelValues("daily_limit_exceeded").Inc()
			// assuming we sent the right parameters, the error indicates the daily rate limit exceeded
			return nil, ErrDailyRateLimitExceeded
		}
		requestTotal.WithLabelValues(fmt.Sprintf("failed_%d", resp.StatusCode)).Inc()
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed request (%d): %s", resp.StatusCode, body)
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		requestTotal.WithLabelValues("failed_read_res").Inc()
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}
	c.logger.Debugf("aptos response body: %s", body)

	var result R
	if err := json.Unmarshal(body, &result); err != nil {
		requestTotal.WithLabelValues("failed_decode_res").Inc()
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	requestTotal.WithLabelValues("success").Inc()

	return &result, nil
}

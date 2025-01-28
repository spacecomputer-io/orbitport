package aptosorbital

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	API_URL  = "https://api.aptosorbital.com"
	AUTH_URL = "https://auth.aptosorbital.com/oauth2/token"
)

// ClientOptions contains the configuration options for the Aptos Orbital client.
type ClientOptions struct {
	apiURL       string
	authURL      string
	clientID     string
	clientSecret string
	rateLimit    float64
	rateBurst    int
}

// apply applies the given options to the ClientOptions with defaults.
func (o *ClientOptions) apply(opts ...ClientOption) error {
	for _, opt := range opts {
		opt(o)
	}
	return o.defaults()
}

// defaults sets the default values for the ClientOptions.
func (o *ClientOptions) defaults() error {
	if len(o.apiURL) == 0 {
		o.apiURL = API_URL
	}
	if len(o.authURL) == 0 {
		o.authURL = AUTH_URL
	}
	if len(o.clientID) == 0 {
		return fmt.Errorf("client ID is required")
	}
	if len(o.clientSecret) == 0 {
		return fmt.Errorf("client secret is required")
	}
	if o.rateLimit == 0.0 {
		o.rateLimit = 0.1
	}
	if o.rateBurst == 0 {
		o.rateBurst = 1
	}
	return nil
}

// ClientOption is a function that sets a configuration option.
type ClientOption func(*ClientOptions)

// WithApiURL sets the API URL for the client.
// The default value is "https://api.aptosorbital.com".
func WithApiURL(apiURL string) ClientOption {
	return func(o *ClientOptions) {
		o.apiURL = apiURL
	}
}

// WithAuthURL sets the authentication URL for the client.
// The default value is "https://auth.aptosorbital.com/oauth2/token".
func WithAuthURL(authURL string) ClientOption {
	return func(o *ClientOptions) {
		o.authURL = authURL
	}
}

// WithClientID sets the client ID for the client.
// This option is REQUIRED.
func WithClientID(clientID string) ClientOption {
	return func(o *ClientOptions) {
		o.clientID = clientID
	}
}

// WithClientSecret sets the client secret for the client.
// This option is REQUIRED.
func WithClientSecret(clientSecret string) ClientOption {
	return func(o *ClientOptions) {
		o.clientSecret = clientSecret
	}
}

// WithRateLimit sets the rate limit for the client.
// The default rate limit is 0.1 requests per second with a burst of 1.
func WithRateLimit(rateLimit float64, rateBurst int) ClientOption {
	return func(o *ClientOptions) {
		o.rateLimit = rateLimit
		o.rateBurst = rateBurst
	}
}

// AptosClient is a client for the Aptos Orbital API.
type AptosClient struct {
	opts            *ClientOptions
	limiter         *rate.Limiter
	accessToken     string
	tokenExpiration int64
	authLock        sync.RWMutex
}

// NewClient creates a new AptosClient with the given options.
func NewClient(opts ...ClientOption) (*AptosClient, error) {
	o := &ClientOptions{}
	if err := o.apply(opts...); err != nil {
		return nil, err
	}

	limiter := rate.NewLimiter(rate.Limit(o.rateLimit), o.rateBurst)
	return &AptosClient{
		opts:    o,
		limiter: limiter,
	}, nil
}

// GetTrueRandomnessSeed retrieves a true randomness seed from the Aptos Orbital API.
// TODO: handle response data properly.
func (c *AptosClient) GetTrueRandomnessSeed(noSig, numChunk int) (interface{}, error) {
	if !c.limiter.Allow() {
		// TODO: think about how to handle rate limit exceeded.
		// currently the rate limiting is applied to the entire service
		// as we don't distinguish between different callers
		return nil, fmt.Errorf("rate limit exceeded")
	}

	headers, err := c.getHeaders()
	if err != nil {
		return nil, err
	}

	urlStr := fmt.Sprintf("%s/services/v1/trng_seed?no_sig=%d&num_chunk=%d", c.opts.apiURL, noSig, numChunk)
	result, err := c.makeRequest("GET", urlStr, headers, nil, nil)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// getHeaders retrieves the headers for making a request.
func (c *AptosClient) getHeaders() (map[string]string, error) {
	token, expiration := c.getAccessToken()

	if token == "" || time.Now().Unix() >= expiration {
		t, err := c.authenticate()
		if err != nil {
			return nil, err
		}
		token = t
	}

	return map[string]string{
		"Authorization": "Bearer " + token,
	}, nil
}

// makeRequest makes a request according to the given parameters.
// TODO: manage request data properly.
func (c *AptosClient) makeRequest(method, urlStr string, headers map[string]string, data interface{}, params map[string]string) (map[string]interface{}, error) {
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

	req, err := http.NewRequest(method, urlStr, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if data != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to reach the server: %v", err)
	}
	defer resp.Body.Close()

	// TODO: handle response status codes properly.
	if resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed: %s", body)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// authenticate retrieves an access token from the OAuth2 endpoint.
func (c *AptosClient) authenticate() (string, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.opts.clientID)
	data.Set("client_secret", c.opts.clientSecret)
	data.Set("scope", "services/read")

	req, err := http.NewRequest("POST", c.opts.authURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create OAuth request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to reach OAuth endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("authentication failed: %s", body)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode OAuth response: %v", err)
	}

	accessToken, ok := result["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("access token not found in response")
	}
	expiresIn, ok := result["expires_in"].(float64)
	if !ok {
		return "", fmt.Errorf("token expiration not found in response")
	}
	tokenExpiration := time.Now().Unix() + int64(expiresIn) - 60

	c.updateToken(accessToken, tokenExpiration)

	return accessToken, nil
}

// updateToken updates the access token and its expiration time.
func (c *AptosClient) updateToken(accessToken string, expiration int64) {
	c.authLock.Lock()
	defer c.authLock.Unlock()

	c.accessToken = accessToken
	c.tokenExpiration = expiration
}

// getAccessToken retrieves the access token and its expiration time.
// Don't access the properties directly, use this method instead for thread safety.
func (c *AptosClient) getAccessToken() (string, int64) {
	c.authLock.RLock()
	defer c.authLock.RUnlock()

	return c.accessToken, c.tokenExpiration
}

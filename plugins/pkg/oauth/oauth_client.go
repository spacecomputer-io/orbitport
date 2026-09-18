package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	logging "github.com/ipfs/go-log"
)

type AccessToken struct {
	Value      string
	Expiration int64
}

type OAuthClient struct {
	logger       *logging.ZapEventLogger
	authLock     sync.RWMutex
	clientID     string
	clientSecret string
	authURL      string
	authLabel    string
	timeout      time.Duration
	lastToken    *AccessToken
}

func NewOAuthClient(clientID, clientSecret, authURL string, timeout time.Duration) *OAuthClient {
	return &OAuthClient{
		logger:       logging.Logger("auth"),
		clientID:     clientID,
		clientSecret: clientSecret,
		authURL:      authURL,
		authLabel:    metricsEndpointLabel(authURL),
		timeout:      timeout,
	}
}

func metricsEndpointLabel(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "invalid_endpoint"
	}
	if parsed.Host != "" {
		if parsed.Scheme != "" {
			return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
		}
		return parsed.Host
	}
	return "invalid_endpoint"
}

// authenticate retrieves an access token from the OAuth2 endpoint.
func (c *OAuthClient) GetAccessToken(ctx context.Context) (*AccessToken, error) {
	// acquire the lock to prevent multiple authentication requests at the same time
	c.authLock.Lock()
	defer c.authLock.Unlock()

	if c.lastToken != nil && time.Now().Unix() < c.lastToken.Expiration {
		c.logger.Debug("returning cached token")
		return c.lastToken, nil
	}
	c.logger.Debug("access token nil or expired, authenticating with endpoint %s", c.authURL)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)
	data.Set("scope", "services/read")

	req, err := http.NewRequestWithContext(ctx, "POST", c.authURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		authStatusCollector.WithLabelValues(c.authLabel).Set(authStatusBadRequest)
		return nil, fmt.Errorf("bad request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: c.timeout}
	resp, err := client.Do(req)
	if err != nil {
		authStatusCollector.WithLabelValues(c.authLabel).Set(authStatusBadEndpoint)
		return nil, fmt.Errorf("bad endpoint: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			c.logger.Warnf("failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		c.logger.Warnf("failed with code %d: %s", resp.StatusCode, body)
		authStatusCollector.WithLabelValues(c.authLabel).Set(authStatusFailedResponse)
		return nil, fmt.Errorf("failed with code %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		authStatusCollector.WithLabelValues(c.authLabel).Set(authStatusBadResponse)
		return nil, fmt.Errorf("bad response: %v", err)
	}

	accessToken, ok := result["access_token"].(string)
	if !ok {
		authStatusCollector.WithLabelValues(c.authLabel).Set(authStatusBadResponse)
		return nil, fmt.Errorf("access token not found")
	}
	expiresIn, ok := result["expires_in"].(float64)
	if !ok {
		authStatusCollector.WithLabelValues(c.authLabel).Set(authStatusBadResponse)
		return nil, fmt.Errorf("token expiration not found")
	}
	tokenExpiration := time.Now().Unix() + int64(expiresIn) - 60

	token := &AccessToken{
		Value:      accessToken,
		Expiration: tokenExpiration,
	}
	c.lastToken = token
	authStatusCollector.WithLabelValues(c.authLabel).Set(authStatusAuthenticated)
	authExpireCollector.WithLabelValues(c.authLabel).Set(float64(tokenExpiration))

	c.logger.Infof("access token updated with expiration %d", tokenExpiration)

	return token, nil
}

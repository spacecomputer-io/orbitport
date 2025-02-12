package aptosorbital

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// authenticate retrieves an access token from the OAuth2 endpoint.
func (c *AptosClient) authenticate(ctx context.Context) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.opts.clientID)
	data.Set("client_secret", c.opts.clientSecret)
	data.Set("scope", "services/read")

	req, err := http.NewRequestWithContext(ctx, "POST", c.opts.authURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		authStatusCollector.Set(authStatusBadRequest)
		return "", fmt.Errorf("failed to create OAuth request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	c.logger.Debugf("authenticating with OAuth endpoint %s", c.opts.authURL)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		authStatusCollector.Set(authStatusBadEndpoint)
		return "", fmt.Errorf("failed to reach OAuth endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		authStatusCollector.Set(authStatusFailedResponse)
		return "", fmt.Errorf("failed with code %d: %s", resp.StatusCode, body)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		authStatusCollector.Set(authStatusBadResponse)
		return "", fmt.Errorf("failed to decode OAuth response: %v", err)
	}

	accessToken, ok := result["access_token"].(string)
	if !ok {
		authStatusCollector.Set(authStatusBadResponse)
		return "", fmt.Errorf("access token not found in response")
	}
	expiresIn, ok := result["expires_in"].(float64)
	if !ok {
		authStatusCollector.Set(authStatusBadResponse)
		return "", fmt.Errorf("token expiration not found in response")
	}
	tokenExpiration := time.Now().Unix() + int64(expiresIn) - 60

	c.updateToken(accessToken, tokenExpiration)

	c.logger.Infof("access token updated with expiration %d", tokenExpiration)

	return accessToken, nil
}

// updateToken updates the access token and its expiration time.
func (c *AptosClient) updateToken(accessToken string, expiration int64) {
	c.authLock.Lock()
	defer c.authLock.Unlock()

	c.accessToken = accessToken
	c.tokenExpiration = expiration

	authExpireCollector.Set(float64(expiration))
	authStatusCollector.Set(authStatusAuthenticated)
}

// getAccessToken retrieves the access token and its expiration time.
// Don't access the properties directly, use this method instead for thread safety.
func (c *AptosClient) getAccessToken() (string, int64) {
	c.authLock.RLock()
	defer c.authLock.RUnlock()

	return c.accessToken, c.tokenExpiration
}

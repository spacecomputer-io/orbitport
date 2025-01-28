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
)

const (
	API_URL  = "https://api.aptosorbital.com"
	AUTH_URL = "https://auth.aptosorbital.com/oauth2/token"
)

type AptosClient struct {
	clientID        string
	clientSecret    string
	accessToken     string
	tokenExpiration int64
	authLock        sync.RWMutex
}

func NewAptosClient(clientID, clientSecret string) *AptosClient {
	return &AptosClient{
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

func (c *AptosClient) GetTrueRandomnessSeed(noSig, numChunk int) (interface{}, error) {
	headers, err := c.getHeaders()
	if err != nil {
		return nil, err
	}

	urlStr := fmt.Sprintf("%s/services/v1/trng_seed?no_sig=%d&num_chunk=%d", API_URL, noSig, numChunk)
	result, err := c.makeRequest("GET", urlStr, headers, nil, nil)
	if err != nil {
		return nil, err
	}

	return result, nil
}

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

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed: %s", body)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *AptosClient) authenticate() (string, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)
	data.Set("scope", "services/read")

	req, err := http.NewRequest("POST", AUTH_URL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to reach OAuth2 endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("authentication failed: %s", body)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
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

func (c *AptosClient) updateToken(accessToken string, expiration int64) {
	c.authLock.Lock()
	defer c.authLock.Unlock()

	c.accessToken = accessToken
	c.tokenExpiration = expiration
}

func (c *AptosClient) getAccessToken() (string, int64) {
	c.authLock.RLock()
	defer c.authLock.RUnlock()

	return c.accessToken, c.tokenExpiration
}

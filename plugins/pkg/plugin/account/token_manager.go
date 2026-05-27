package account

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
)

// refreshLead is how long before expiry the background goroutine refreshes the token.
const refreshLead = 5 * time.Minute

// cachedToken bundles the active access token with its expiry so both can be
// read/written atomically via utils.Locked.
type cachedToken struct {
	accessToken string
	expiresAt   time.Time
}

// tokenManager mints + caches an Auth0 M2M access token via the
// client_credentials grant. Initial fetch is blocking + fail-closed. A
// background goroutine refreshes the token ~5 min before expiry.
type tokenManager struct {
	domain       string
	audience     string
	clientID     string
	clientSecret string
	httpClient   *http.Client
	logger       *utils.Logger

	cache   *utils.Locked[cachedToken]
	threads utils.ThreadControl
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func newTokenManager(cfg *accountConfig) *tokenManager {
	return &tokenManager{
		domain:       cfg.Auth0Domain,
		audience:     cfg.Auth0Audience,
		clientID:     cfg.Auth0ClientID,
		clientSecret: cfg.Auth0ClientSecret,
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.HTTPTimeoutSecs) * time.Second,
		},
		logger:  utils.GetLogger("orbitport:account:token"),
		cache:   utils.NewLocked(cachedToken{}),
		threads: utils.NewThreadControl(),
	}
}

// start performs the initial blocking fetch then launches the background
// refresh goroutine. Returns an error when the initial fetch fails.
func (t *tokenManager) start(ctx context.Context) error {
	if err := t.refresh(ctx); err != nil {
		return fmt.Errorf("initial Auth0 M2M token fetch failed: %w", err)
	}
	t.threads.Go(t.refreshLoop)
	return nil
}

// close terminates the background refresh goroutine.
func (t *tokenManager) close() {
	t.threads.Close()
}

// token returns the cached access token. Returns an error when no token is
// available — callers should treat this as transport failure.
func (t *tokenManager) token() (string, error) {
	cached := t.cache.Get()
	if cached.accessToken == "" {
		return "", fmt.Errorf("account plugin: no Auth0 M2M token available")
	}
	if time.Now().After(cached.expiresAt) {
		return "", fmt.Errorf("account plugin: cached Auth0 M2M token expired")
	}
	return cached.accessToken, nil
}

func (t *tokenManager) refreshLoop(ctx context.Context) {
	for {
		cached := t.cache.Get()
		wait := time.Until(cached.expiresAt) - refreshLead
		if wait < 30*time.Second {
			wait = 30 * time.Second
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		refreshCtx, cancel := context.WithTimeout(ctx, t.httpClient.Timeout)
		if err := t.refresh(refreshCtx); err != nil {
			t.logger.Warnf("Auth0 M2M token refresh failed: %v", err)
		}
		cancel()
	}
}

func (t *tokenManager) refresh(ctx context.Context) error {
	tokenURL := "https://" + t.domain + "/oauth/token"
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", t.clientID)
	form.Set("client_secret", t.clientSecret)
	form.Set("audience", t.audience)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("post token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("auth0 token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var parsed tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return fmt.Errorf("decode token response: %w", err)
	}
	if parsed.AccessToken == "" {
		return fmt.Errorf("auth0 token response missing access_token")
	}
	if parsed.ExpiresIn <= 0 {
		return fmt.Errorf("auth0 token response missing expires_in")
	}

	t.cache.Set(cachedToken{
		accessToken: parsed.AccessToken,
		expiresAt:   time.Now().Add(time.Duration(parsed.ExpiresIn) * time.Second),
	})

	t.logger.Debugf("Auth0 M2M token refreshed, expires_in=%ds", parsed.ExpiresIn)
	return nil
}

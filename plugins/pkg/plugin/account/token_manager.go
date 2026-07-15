package account

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

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
)

// refreshLead is how long before expiry a cached token is treated as stale, so
// callers never receive a token that could expire mid-request.
const refreshLead = 5 * time.Minute

// cachedToken bundles the active access token with its expiry so both can be
// read/written atomically via utils.Locked.
type cachedToken struct {
	accessToken string
	expiresAt   time.Time
}

// tokenManager mints + caches an Auth0 M2M access token via the
// client_credentials grant. Tokens are fetched on demand: token() returns the
// cached value while it is still fresh and refreshes inline once it is missing
// or within refreshLead of expiry. refreshMu collapses concurrent refreshes
// into a single Auth0 call.
type tokenManager struct {
	domain       string
	audience     string
	clientID     string
	clientSecret string
	httpClient   *http.Client
	logger       *utils.Logger

	cache     *utils.Locked[cachedToken]
	refreshMu sync.Mutex
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
		logger: utils.GetLogger("orbitport:account:token"),
		cache:  utils.NewLocked(cachedToken{}),
	}
}

// start performs a blocking initial fetch so the plugin fails closed when Auth0
// is misconfigured at boot. Subsequent refreshes happen on demand via token().
func (t *tokenManager) start(ctx context.Context) error {
	if err := t.refresh(ctx); err != nil {
		return fmt.Errorf("initial Auth0 M2M token fetch failed: %w", err)
	}
	return nil
}

// token returns a valid access token, refreshing inline when the cached token
// is missing or within refreshLead of expiry. Returns an error when a refresh
// is required but fails — callers should treat this as transport failure.
func (t *tokenManager) token(ctx context.Context) (string, error) {
	if tok, ok := t.fresh(t.cache.Get()); ok {
		return tok, nil
	}

	t.refreshMu.Lock()
	defer t.refreshMu.Unlock()

	// Double-check: another goroutine may have refreshed while we waited on the lock.
	if tok, ok := t.fresh(t.cache.Get()); ok {
		return tok, nil
	}

	if err := t.refresh(ctx); err != nil {
		return "", err
	}
	return t.cache.Get().accessToken, nil
}

// fresh reports whether the cached token is non-empty and still outside the
// refreshLead window before expiry.
func (t *tokenManager) fresh(c cachedToken) (string, bool) {
	if c.accessToken == "" {
		return "", false
	}
	if time.Now().After(c.expiresAt.Add(-refreshLead)) {
		return "", false
	}
	return c.accessToken, true
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

package account

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// rewritingTransport replaces the host of every outgoing request with the
// mock server's host so we can exercise refresh() without touching the real
// Auth0 endpoint.
type rewritingTransport struct {
	target string
}

func (r rewritingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u, err := url.Parse(r.target)
	if err != nil {
		return nil, err
	}
	req.URL.Scheme = u.Scheme
	req.URL.Host = u.Host
	return http.DefaultTransport.RoundTrip(req)
}

func newTestTokenManager(t *testing.T, srv *httptest.Server) *tokenManager {
	t.Helper()
	cfg := &accountConfig{
		Auth0Domain:       "auth0.example.com",
		Auth0Audience:     "https://api.example.com",
		Auth0ClientID:     "cid",
		Auth0ClientSecret: "secret",
		HTTPTimeoutSecs:   5,
	}
	tm := newTokenManager(cfg)
	tm.httpClient = &http.Client{
		Timeout:   time.Duration(cfg.HTTPTimeoutSecs) * time.Second,
		Transport: rewritingTransport{target: srv.URL},
	}
	return tm
}

func TestTokenManager_InitialFetchSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/oauth/token", r.URL.Path)
		require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"abc.def.ghi","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	tm := newTestTokenManager(t, srv)
	defer tm.close()

	err := tm.refresh(context.Background())
	require.NoError(t, err)

	got, err := tm.token()
	require.NoError(t, err)
	require.Equal(t, "abc.def.ghi", got)
}

func TestTokenManager_InitialFetchFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer srv.Close()

	tm := newTestTokenManager(t, srv)
	defer tm.close()

	err := tm.refresh(context.Background())
	require.Error(t, err)
}

func TestTokenManager_ExpiredToken_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"abc","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	tm := newTestTokenManager(t, srv)
	defer tm.close()

	require.NoError(t, tm.refresh(context.Background()))

	// Force expiry.
	tm.mu.Lock()
	tm.expiresAt = time.Now().Add(-time.Minute)
	tm.mu.Unlock()

	_, err := tm.token()
	require.Error(t, err)
}

func TestTokenManager_NoTokenYet_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	tm := newTestTokenManager(t, srv)
	defer tm.close()

	_, err := tm.token()
	require.Error(t, err)
}

func TestTokenManager_RefreshCount(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = w.Write([]byte(`{"access_token":"abc","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	tm := newTestTokenManager(t, srv)
	defer tm.close()

	require.NoError(t, tm.refresh(context.Background()))
	require.NoError(t, tm.refresh(context.Background()))
	require.Equal(t, int32(2), atomic.LoadInt32(&calls))
}

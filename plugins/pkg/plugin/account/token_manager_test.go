package account

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
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

	err := tm.refresh(context.Background())
	require.NoError(t, err)

	got, err := tm.token(context.Background())
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

	err := tm.refresh(context.Background())
	require.Error(t, err)
}

// TestTokenManager_LazyFetch verifies token() fetches on demand when the cache
// is empty, without any prior start()/refresh().
func TestTokenManager_LazyFetch(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = w.Write([]byte(`{"access_token":"lazy","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	tm := newTestTokenManager(t, srv)

	got, err := tm.token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "lazy", got)
	require.Equal(t, int32(1), atomic.LoadInt32(&calls))

	// Second call serves from cache; no new Auth0 hit.
	got, err = tm.token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "lazy", got)
	require.Equal(t, int32(1), atomic.LoadInt32(&calls))
}

// TestTokenManager_StaleToken_Refreshes verifies a token within refreshLead of
// expiry is refreshed inline on the next token() call.
func TestTokenManager_StaleToken_Refreshes(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = w.Write([]byte(`{"access_token":"fresh","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	tm := newTestTokenManager(t, srv)
	require.NoError(t, tm.refresh(context.Background()))
	require.Equal(t, int32(1), atomic.LoadInt32(&calls))

	// Force the cached token inside the refreshLead window.
	cached := tm.cache.Get()
	cached.expiresAt = time.Now().Add(refreshLead / 2)
	tm.cache.Set(cached)

	got, err := tm.token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "fresh", got)
	require.Equal(t, int32(2), atomic.LoadInt32(&calls))
}

// TestTokenManager_LazyFetchFailure verifies token() surfaces an error when the
// on-demand refresh fails and no usable token is cached.
func TestTokenManager_LazyFetchFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer srv.Close()

	tm := newTestTokenManager(t, srv)

	_, err := tm.token(context.Background())
	require.Error(t, err)
}

// TestTokenManager_SingleFlight verifies concurrent token() callers collapse
// into a single Auth0 refresh.
func TestTokenManager_SingleFlight(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(50 * time.Millisecond) // widen the contention window
		_, _ = w.Write([]byte(`{"access_token":"shared","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	tm := newTestTokenManager(t, srv)

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			got, err := tm.token(context.Background())
			require.NoError(t, err)
			require.Equal(t, "shared", got)
		}()
	}
	wg.Wait()

	require.Equal(t, int32(1), atomic.LoadInt32(&calls))
}

func TestTokenManager_RefreshCount(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = w.Write([]byte(`{"access_token":"abc","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	tm := newTestTokenManager(t, srv)

	require.NoError(t, tm.refresh(context.Background()))
	require.NoError(t, tm.refresh(context.Background()))
	require.Equal(t, int32(2), atomic.LoadInt32(&calls))
}

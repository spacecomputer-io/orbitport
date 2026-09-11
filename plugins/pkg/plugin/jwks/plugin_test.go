package jwks

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

const testJWKS = `{"keys":[{"kty":"EC","crv":"P-256","kid":"v1","x":"abc","y":"def"}]}`

// mockIssuer is an in-process gRPC patissuer plugin serving a swappable JWKS.
type mockIssuer struct {
	proto.UnimplementedPatIssuerPluginServer

	mu    sync.Mutex
	jwks  string
	err   error
	calls int
}

func (m *mockIssuer) GetJwks(context.Context, *proto.GetJwksRequest) (*proto.GetJwksResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return &proto.GetJwksResponse{JwksJson: m.jwks}, nil
}

func (m *mockIssuer) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func startMockIssuer(t *testing.T, m *mockIssuer) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	proto.RegisterPatIssuerPluginServer(srv, m)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

// main() wires the ORBITPORT prefix via core.ReadFromEnv; tests must do it
// themselves or viper never sees t.Setenv values.
func bindEnv(t *testing.T) {
	t.Helper()
	viper.SetEnvPrefix("ORBITPORT")
	viper.AutomaticEnv()
}

func newTestPlugin(t *testing.T, m *mockIssuer) *Plugin {
	t.Helper()
	bindEnv(t)
	t.Setenv("ORBITPORT_JWKS_PATISSUER_PLUGIN", startMockIssuer(t, m))
	p, err := NewPlugin()
	require.NoError(t, err)
	return p
}

// get drives the real handler through an httptest recorder so the response
// headers and status are exercised, not just the cache.
func get(t *testing.T, p *Plugin) *http.Response {
	t.Helper()
	rec := httptest.NewRecorder()
	p.handleJWKS(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	return rec.Result()
}

func TestServesIssuerKeySet(t *testing.T) {
	p := newTestPlugin(t, &mockIssuer{jwks: testJWKS})

	resp := get(t, p)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	require.Equal(t, "max-age=300", resp.Header.Get("Cache-Control"))

	body := make([]byte, len(testJWKS))
	_, err := resp.Body.Read(body)
	require.NoError(t, err)
	require.Equal(t, testJWKS, string(body))
}

func TestCachesBetweenRequests(t *testing.T) {
	m := &mockIssuer{jwks: testJWKS}
	p := newTestPlugin(t, m)

	for range 5 {
		require.Equal(t, http.StatusOK, get(t, p).StatusCode)
	}
	// The route is public: without the cache every anonymous request would
	// fan through to the issuer.
	require.Equal(t, 1, m.callCount())
}

func TestIssuerFailureIs503(t *testing.T) {
	p := newTestPlugin(t, &mockIssuer{err: errors.New("issuer down")})

	resp := get(t, p)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Empty(t, resp.Header.Get("Cache-Control"), "an error must not be cached by clients")
}

// Fail closed: publishing an empty set as a 200 reads as "this issuer has no
// keys" and makes every verifier reject every PAT.
func TestEmptyKeySetIsRefused(t *testing.T) {
	m := &mockIssuer{jwks: ""}
	p := newTestPlugin(t, m)

	require.Equal(t, http.StatusServiceUnavailable, get(t, p).StatusCode)

	// Nothing empty was cached, so the next request retries the issuer.
	require.Equal(t, http.StatusServiceUnavailable, get(t, p).StatusCode)
	require.Equal(t, 2, m.callCount())
}

func TestPatIssuerPluginAddressIsRequired(t *testing.T) {
	bindEnv(t)
	t.Setenv("ORBITPORT_JWKS_PATISSUER_PLUGIN", "")
	_, err := NewPlugin()
	require.Error(t, err)
	require.Contains(t, err.Error(), "ORBITPORT_JWKS_PATISSUER_PLUGIN")
}

func TestConcurrentRequestsCollapseToOneFetch(t *testing.T) {
	m := &mockIssuer{jwks: testJWKS}
	p := newTestPlugin(t, m)

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = get(t, p)
		}()
	}
	wg.Wait()

	require.Equal(t, 1, m.callCount(), "a burst of requests must not fan out to the issuer")
}

package aptosorbital

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/testutils"
	"github.com/spacecomputer-io/orbitport/plugins/proto"
	"github.com/stretchr/testify/require"
)

func TestPluginGetTrngFallsBackOnNoDataAvailable(t *testing.T) {
	mockAuth := testutils.NewMockServer(true, `{"access_token": "11111111111111", "expires_in": 3600, "token_type": "Bearer"}`)
	defer mockAuth.Close()

	mockAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code": "NO_DATA_AVAILABLE", "message": "No randomness available. All data has been consumed."}`))
	}))
	defer mockAPI.Close()

	client, err := NewClient(
		WithClientID("client_id"),
		WithClientSecret("client_secret"),
		WithAuthURL(mockAuth.URL),
		WithApiURL(mockAPI.URL),
		WithRateLimit(1, 2),
	)
	require.NoError(t, err)

	p := &Plugin{aptosClient: client}

	resp, err := p.GetTrng(context.Background(), &proto.TrngRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Empty(t, resp.Values)
	require.Empty(t, resp.Sig)
}

func TestPluginGetTrngReturnsErrorOnUpstreamFailure(t *testing.T) {
	mockAuth := testutils.NewMockServer(false, "")
	defer mockAuth.Close()
	mockAPI := testutils.NewMockServer(true, `[]`)
	defer mockAPI.Close()

	client, err := NewClient(
		WithClientID("client_id"),
		WithClientSecret("client_secret"),
		WithAuthURL(mockAuth.URL),
		WithApiURL(mockAPI.URL),
		WithRateLimit(1, 2),
	)
	require.NoError(t, err)

	p := &Plugin{aptosClient: client}

	resp, err := p.GetTrng(context.Background(), &proto.TrngRequest{})
	require.Error(t, err)
	require.Nil(t, resp)
}

package aptosorbital

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClientOptions(t *testing.T) {
	tests := []struct {
		name          string
		opts          []ClientOption
		expecectedErr error
	}{
		{
			name:          "empty options",
			opts:          nil,
			expecectedErr: fmt.Errorf("client ID is required"),
		},
		{
			name: "with required options",
			opts: []ClientOption{
				WithClientID("client_id"),
				WithClientSecret("client_secret"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &ClientOptions{}
			err := o.apply(tt.opts...)
			require.Equal(t, tt.expecectedErr, err)
		})
	}
}

func TestExampleTRNGResponse(t *testing.T) {
	tests := []struct {
		name    string
		resp    string
		errored bool
	}{
		{
			name:    "empty response",
			errored: true,
		},
		{
			name: "valid response",
			resp: `[{"chunk": "aaa2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa", "signature": "aaa6022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa"}]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r trngSeedResponse
			err := json.Unmarshal([]byte(tt.resp), &r)
			if tt.errored {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			commonRandSeed := r[0].toCommonRandomSeed()
			require.Equal(t, r[0].Chunk, commonRandSeed.Value)
		})
	}
}

func TestGetTrueRandomnessSeedWithMockResponses(t *testing.T) {
	mockAuth := newMockServer(`{"access_token": "11111111111111", "expires_in": 3600, "token_type": "Bearer"}`)
	mockApi := newMockServer(`[{"chunk": "aaa2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa", "signature": "aaa6022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa"}]`)

	go mockAuth.run(":3050")
	go mockApi.run(":3051")

	client, err := NewClient(
		WithClientID("client_id"),
		WithClientSecret("client_secret"),
		WithAuthURL("http://localhost:3050"),
		WithApiURL("http://localhost:3051"),
		WithRateLimit(1, 2),
	)
	require.NoError(t, err)

	t.Run("happy path", func(t *testing.T) {
		seed, err := client.GetTrueRandomnessSeed(false, 1)
		require.NoError(t, err)
		require.Equal(t, "aaa2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa", seed.Value)
		require.Equal(t, "aaa6022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa", seed.Sig)
	})

	t.Run("rate limit exceeded", func(t *testing.T) {
		_, _ = client.GetTrueRandomnessSeed(false, 1)
		_, _ = client.GetTrueRandomnessSeed(false, 1)
		_, _ = client.GetTrueRandomnessSeed(false, 1)
		_, err := client.GetTrueRandomnessSeed(false, 1)
		require.Error(t, err)
		require.Equal(t, ErrRateLimitExceeded, err)
	})

	t.Run("failed authentication", func(t *testing.T) {
		client, err := NewClient(
			WithClientID("client_id"),
			WithClientSecret("client_secret"),
			WithAuthURL("http://localhost:3050"),
			WithApiURL("http://localhost:3051"),
			WithRateLimit(1, 2),
		)
		require.NoError(t, err)

		_, err = client.GetTrueRandomnessSeed(false, 1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "authentication failed")
	})
}

func newMockServer(responses ...string) *mockServer {
	return &mockServer{
		responses: responses,
	}
}

type mockServer struct {
	responses []string
	lock      sync.Mutex
}

func (m *mockServer) run(addr string) {
	_ = http.ListenAndServe(addr, m)
}

func (m *mockServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if len(m.responses) == 0 {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, m.responses[0])
	m.responses = m.responses[1:]
}

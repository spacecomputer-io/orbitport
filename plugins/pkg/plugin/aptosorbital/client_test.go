package aptosorbital

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/testutils"
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
		name     string
		resp     string
		errored  bool
		expected []string
	}{
		{
			name:    "empty response",
			errored: true,
		},
		{
			name: "valid response",
			resp: `[{"chunk": "aaa2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa", "signature": "aaa6022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa"}]`,
			expected: []string{
				"aaa2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa",
			},
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
			values := make([]string, 0, len(r))
			for _, seed := range r {
				values = append(values, seed.Chunk)
			}

			require.Equal(t, tt.expected, values)
		})
	}
}

func TestGetTrueRandomnessSeedWithMockResponses(t *testing.T) {
	mockAuth := testutils.NewMockServer(true, `{"access_token": "11111111111111", "expires_in": 3600, "token_type": "Bearer"}`)
	defer mockAuth.Close()
	mockApi := testutils.NewMockServer(true, `[{"chunk": "aaa2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa", "signature": "aaa6022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa"}]`)
	defer mockApi.Close()

	client, err := NewClient(
		WithClientID("client_id"),
		WithClientSecret("client_secret"),
		WithAuthURL(mockAuth.URL),
		WithApiURL(mockApi.URL),
		WithRateLimit(1, 2),
	)
	require.NoError(t, err)

	t.Run("happy path", func(t *testing.T) {
		seed, err := client.GetTrueRandomnessSeed(context.Background(), false, 1)
		require.NoError(t, err)
		require.Len(t, seed.Values, 1)
		require.Equal(t,
			"aaa2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa",
			seed.Values[0],
		)
		require.Equal(t,
			"aaa6022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa",
			seed.Sig,
		)
	})

	t.Run("rate limit exceeded", func(t *testing.T) {
		_, _ = client.GetTrueRandomnessSeed(context.Background(), false, 1)
		_, _ = client.GetTrueRandomnessSeed(context.Background(), false, 1)
		_, _ = client.GetTrueRandomnessSeed(context.Background(), false, 1)
		_, err := client.GetTrueRandomnessSeed(context.Background(), false, 1)
		require.Error(t, err)
		require.Equal(t, ErrRateLimitExceeded, err)
	})

	t.Run("empty api responses", func(t *testing.T) {
		// Mock API returns empty list
		mockApi := testutils.NewMockServer(true, "[]")
		defer mockApi.Close()

		// Create new client using existing mockAuth.URL from parent scope
		client, err := NewClient(
			WithClientID("client_id"),
			WithClientSecret("client_secret"),
			WithAuthURL(mockAuth.URL),
			WithApiURL(mockApi.URL),
			WithRateLimit(1, 2),
		)
		require.NoError(t, err)

		_, err = client.GetTrueRandomnessSeed(context.Background(), false, 1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty response from trng_seed")
	})

	t.Run("failed authentication", func(t *testing.T) {
		mockAuth := testutils.NewMockServer(false, "")
		require.NoError(t, err)

		// creating a new client (clean credentials).
		// the authentication server will return an error
		// so the client will fail to authenticate.
		client, err := NewClient(
			WithClientID("client_id"),
			WithClientSecret("client_secret"),
			WithAuthURL(mockAuth.URL),
			WithApiURL(mockApi.URL),
			WithRateLimit(1, 2),
		)
		require.NoError(t, err)
		require.NoError(t, err)

		_, err = client.GetTrueRandomnessSeed(context.Background(), false, 1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "authentication failed")
	})

	t.Run("dead ctx", func(t *testing.T) {
		// creating a new client (clean credentials).
		// the authentication server will return an error
		// so the client will fail to authenticate.
		client, err := NewClient(
			WithClientID("client_id"),
			WithClientSecret("client_secret"),
			WithAuthURL(mockAuth.URL),
			WithApiURL(mockApi.URL),
			WithRateLimit(1, 2),
		)
		require.NoError(t, err)

		require.NoError(t, err)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = client.GetTrueRandomnessSeed(ctx, false, 1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "context canceled")
	})
}

func TestGetTrueRandomnessSeedNoDataAvailable(t *testing.T) {
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

	_, err = client.GetTrueRandomnessSeed(context.Background(), true, 1)
	require.ErrorIs(t, err, ErrNoDataAvailable)
}

func TestGetTrueRandomnessSeedNoDataAvailableWithDifferentStatus(t *testing.T) {
	mockAuth := testutils.NewMockServer(true, `{"access_token": "11111111111111", "expires_in": 3600, "token_type": "Bearer"}`)
	defer mockAuth.Close()

	mockAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
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

	_, err = client.GetTrueRandomnessSeed(context.Background(), true, 1)
	require.ErrorIs(t, err, ErrNoDataAvailable)
}

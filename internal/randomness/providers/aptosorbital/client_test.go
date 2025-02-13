package aptosorbital

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/spacecoinxyz/orbitport/internal/randomness/providers"
	"github.com/spacecoinxyz/orbitport/internal/testutils"
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
	mockAuth := testutils.NewMockServer(true, `{"access_token": "11111111111111", "expires_in": 3600, "token_type": "Bearer"}`)
	mockApi := testutils.NewMockServer(true, `[{"chunk": "aaa2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa", "signature": "aaa6022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa"}]`)

	authPort := 3050
	apiPort := 3051

	go mockAuth.ListenAndServe(fmt.Sprintf(":%d", authPort))
	go mockApi.ListenAndServe(fmt.Sprintf(":%d", apiPort))

	client, err := NewClient(
		WithClientID("client_id"),
		WithClientSecret("client_secret"),
		WithAuthURL(fmt.Sprintf("http://localhost:%d", authPort)),
		WithApiURL(fmt.Sprintf("http://localhost:%d", apiPort)),
		WithRateLimit(1, 2),
	)
	require.NoError(t, err)

	t.Run("happy path", func(t *testing.T) {
		seed, err := client.GetTrueRandomnessSeed(context.Background(), false, 1)
		require.NoError(t, err)
		require.Equal(t, "aaa2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa", seed.Value)
		require.Equal(t, "aaa6022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa", seed.Sig)
		require.Equal(t, providers.RandSourceAptosOrbital, seed.Src)
	})

	t.Run("rate limit exceeded", func(t *testing.T) {
		_, _ = client.GetTrueRandomnessSeed(context.Background(), false, 1)
		_, _ = client.GetTrueRandomnessSeed(context.Background(), false, 1)
		_, _ = client.GetTrueRandomnessSeed(context.Background(), false, 1)
		_, err := client.GetTrueRandomnessSeed(context.Background(), false, 1)
		require.Error(t, err)
		require.Equal(t, ErrRateLimitExceeded, err)
	})

	t.Run("failed authentication", func(t *testing.T) {
		mockAuth := testutils.NewMockServer(false, "")
		go mockAuth.ListenAndServe(fmt.Sprintf(":%d", authPort-1))
		// creating a new client (clean credentials).
		// the authentication server will return an error
		// so the client will fail to authenticate.
		client, err := NewClient(
			WithClientID("client_id"),
			WithClientSecret("client_secret"),
			WithAuthURL(fmt.Sprintf("http://localhost:%d", authPort-1)),
			WithApiURL(fmt.Sprintf("http://localhost:%d", apiPort)),
			WithRateLimit(1, 2),
		)
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
			WithAuthURL(fmt.Sprintf("http://localhost:%d", authPort)),
			WithApiURL(fmt.Sprintf("http://localhost:%d", apiPort)),
			WithRateLimit(1, 2),
		)
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = client.GetTrueRandomnessSeed(ctx, false, 1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "context canceled")
	})
}

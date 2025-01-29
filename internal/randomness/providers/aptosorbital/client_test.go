package aptosorbital

import (
	"encoding/json"
	"fmt"
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
			resp: `{
				"chunk": "a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890",
				"signature": "3046022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890"
			}`,
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
			commonRandSeed := r.toRandomSeed()
			require.Equal(t, r.Chunk, commonRandSeed.Value)
		})
	}
}

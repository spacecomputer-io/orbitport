package aptosorbital

import (
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

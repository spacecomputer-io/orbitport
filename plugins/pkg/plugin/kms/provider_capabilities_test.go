package kms

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRequireDeleteKeyProvider(t *testing.T) {
	for _, test := range []struct {
		scheme   string
		provider kmsProvider
	}{
		{scheme: schemeTransit, provider: newTransitProvider(nil)},
		{scheme: schemeEthereum, provider: newEthereumProvider(nil)},
		{scheme: schemePQC, provider: newPQCProvider(nil)},
	} {
		t.Run(test.scheme, func(t *testing.T) {
			deleter, err := requireDeleteKeyProvider(test.provider, test.scheme)
			if test.scheme == schemeTransit {
				require.NoError(t, err)
				require.Same(t, test.provider, deleter)
				return
			}
			require.Nil(t, deleter)
			require.Equal(t, codes.Unimplemented, status.Code(err))
			require.Equal(t, test.scheme+" key deletion is not implemented", status.Convert(err).Message())
		})
	}
}

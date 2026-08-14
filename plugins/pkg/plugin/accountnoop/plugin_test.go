package accountnoop

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

func TestHoldGrantsAndReportsTenant(t *testing.T) {
	t.Setenv("ORBITPORT_ACCOUNTNOOP_KMS_TENANT", "e2e-tenant")
	p, err := NewPlugin()
	require.NoError(t, err)

	resp, err := p.Hold(context.Background(), &proto.HoldRequest{
		ClientId: "acct-1",
		Jti:      "pat-jti-1",
		Units:    1,
	})
	require.NoError(t, err)
	require.True(t, resp.GetOk())
	require.NotEmpty(t, resp.GetLedgerId())
	require.Equal(t, "e2e-tenant", resp.GetKmsTenant())
}

// The gateway refuses a PAT whose hold resolves no tenancy, so a noop that
// forgot to set one would fail closed and look like a gateway bug.
func TestHoldAlwaysReportsATenant(t *testing.T) {
	p, err := NewPlugin()
	require.NoError(t, err)

	resp, err := p.Hold(context.Background(), &proto.HoldRequest{ClientId: "acct-1"})
	require.NoError(t, err)
	require.Equal(t, defaultTenant, resp.GetKmsTenant())
}

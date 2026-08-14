package accountnoop

import (
	"context"
	"os"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

// defaultTenant is deliberately not an account id or an Auth0 sub: it must be
// obvious in a KMS namespace that the keys came from a noop plugin, and it must
// differ from whatever a test PAT claims so the gateway's choice of source is
// observable.
const defaultTenant = "noop-tenant"

// Plugin implements a development-only account plugin that grants every hold
// without touching the dashboard. It exists so the PAT path can be exercised
// end to end — mint, sign, verify, serve — without standing up the dashboard
// backend and its Auth0 M2M credentials.
type Plugin struct {
	proto.AccountPluginServer

	kmsTenant string
}

// NewPlugin creates a noop account plugin for local development environments.
func NewPlugin() (*Plugin, error) {
	tenant := os.Getenv("ORBITPORT_ACCOUNTNOOP_KMS_TENANT")
	if tenant == "" {
		tenant = defaultTenant
	}
	utils.GetLogger("orbitport:accountnoop").Warnf(
		"Using noop account plugin: every hold is granted, no credits are charged, "+
			"and no PAT can be revoked. KMS tenancy is pinned to %q. Do not use in production!",
		tenant,
	)
	return &Plugin{kmsTenant: tenant}, nil
}

// Hold grants unconditionally and reports the configured tenancy, standing in
// for the Account row the dashboard would resolve.
func (p *Plugin) Hold(_ context.Context, req *proto.HoldRequest) (*proto.HoldResponse, error) {
	utils.GetLogger("orbitport:accountnoop").Warnf(
		"Granting noop hold for client_id=%s jti=%s op=%s",
		req.GetClientId(), req.GetJti(), req.GetOperation(),
	)
	return &proto.HoldResponse{
		Ok:           true,
		LedgerId:     "noop-ledger",
		BalanceAfter: 0,
		KmsTenant:    p.kmsTenant,
	}, nil
}

func (p *Plugin) Settle(_ context.Context, _ *proto.SettleRequest) (*proto.SettleResponse, error) {
	return &proto.SettleResponse{Ok: true}, nil
}

func (p *Plugin) Release(_ context.Context, _ *proto.ReleaseRequest) (*proto.ReleaseResponse, error) {
	return &proto.ReleaseResponse{Ok: true}, nil
}

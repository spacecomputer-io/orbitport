package account

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func baseValidCfg() *accountConfig {
	return &accountConfig{
		DashboardURL:      "https://dashboard.example.com",
		Auth0Domain:       "auth0.example.com",
		Auth0Audience:     "https://api.example.com",
		Auth0ClientID:     "cid",
		Auth0ClientSecret: "secret",
		CreditsPerUnit:    1,
		HTTPTimeoutSecs:   5,
	}
}

func TestConfig_HTTPSDashboardURL_Accepted(t *testing.T) {
	t.Setenv("ORBITPORT_ACCOUNT_ALLOW_INSECURE", "")
	cfg := baseValidCfg()
	require.NoError(t, cfg.validate())
}

func TestConfig_HTTPDashboardURL_RejectedByDefault(t *testing.T) {
	t.Setenv("ORBITPORT_ACCOUNT_ALLOW_INSECURE", "")
	cfg := baseValidCfg()
	cfg.DashboardURL = "http://dashboard.example.com"
	err := cfg.validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "must be https")
}

func TestConfig_HTTPDashboardURL_AcceptedWithOverride(t *testing.T) {
	t.Setenv("ORBITPORT_ACCOUNT_ALLOW_INSECURE", "true")
	cfg := baseValidCfg()
	cfg.DashboardURL = "http://dashboard.example.com"
	require.NoError(t, cfg.validate())
}

func TestConfig_HTTPDashboardURL_OverrideNotTrueRejected(t *testing.T) {
	t.Setenv("ORBITPORT_ACCOUNT_ALLOW_INSECURE", "1")
	cfg := baseValidCfg()
	cfg.DashboardURL = "http://dashboard.example.com"
	require.Error(t, cfg.validate())
}

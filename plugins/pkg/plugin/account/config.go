package account

import (
	"fmt"
	"os"
	"strings"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	"github.com/spf13/viper"
)

// accountConfig is the configuration for the Account plugin.
type accountConfig struct {
	// DashboardURL is the base URL of the dashboard backend.
	DashboardURL string
	// Auth0Domain is the Auth0 tenant the M2M token is minted against.
	Auth0Domain string
	// Auth0Audience is the audience requested when minting the M2M token.
	Auth0Audience string
	// Auth0ClientID is the M2M application client_id.
	Auth0ClientID string
	// Auth0ClientSecret is the M2M application client_secret.
	Auth0ClientSecret string
	// CreditsPerUnit is the number of credits charged per compute unit.
	CreditsPerUnit uint32
	// HTTPTimeoutSecs is the per-request HTTP timeout (release uses a hard 2s).
	HTTPTimeoutSecs int
}

func trimValue(value string) string {
	return strings.TrimSpace(value)
}

func readFromEnv() *accountConfig {
	setDefaults()

	return &accountConfig{
		DashboardURL:      trimValue(viper.GetString("ACCOUNT_DASHBOARD_URL")),
		Auth0Domain:       trimValue(viper.GetString("ACCOUNT_AUTH0_DOMAIN")),
		Auth0Audience:     trimValue(viper.GetString("ACCOUNT_AUTH0_AUDIENCE")),
		Auth0ClientID:     trimValue(viper.GetString("ACCOUNT_AUTH0_CLIENT_ID")),
		Auth0ClientSecret: trimValue(viper.GetString("ACCOUNT_AUTH0_CLIENT_SECRET")),
		CreditsPerUnit:    viper.GetUint32("ACCOUNT_CREDITS_PER_UNIT"),
		HTTPTimeoutSecs:   viper.GetInt("ACCOUNT_HTTP_TIMEOUT_SECS"),
	}
}

func setDefaults() {
	viper.SetDefault("ACCOUNT_DASHBOARD_URL", "")
	viper.SetDefault("ACCOUNT_AUTH0_DOMAIN", "")
	viper.SetDefault("ACCOUNT_AUTH0_AUDIENCE", "")
	viper.SetDefault("ACCOUNT_AUTH0_CLIENT_ID", "")
	viper.SetDefault("ACCOUNT_AUTH0_CLIENT_SECRET", "")
	viper.SetDefault("ACCOUNT_CREDITS_PER_UNIT", 1)
	viper.SetDefault("ACCOUNT_HTTP_TIMEOUT_SECS", 5)
}

// validate refuses startup when required vars are missing. Fail-closed.
func (c *accountConfig) validate() error {
	missing := []string{}
	if c.DashboardURL == "" {
		missing = append(missing, "ORBITPORT_ACCOUNT_DASHBOARD_URL")
	}
	if c.Auth0Domain == "" {
		missing = append(missing, "ORBITPORT_ACCOUNT_AUTH0_DOMAIN")
	}
	if c.Auth0Audience == "" {
		missing = append(missing, "ORBITPORT_ACCOUNT_AUTH0_AUDIENCE")
	}
	if c.Auth0ClientID == "" {
		missing = append(missing, "ORBITPORT_ACCOUNT_AUTH0_CLIENT_ID")
	}
	if c.Auth0ClientSecret == "" {
		missing = append(missing, "ORBITPORT_ACCOUNT_AUTH0_CLIENT_SECRET")
	}
	if len(missing) > 0 {
		return fmt.Errorf("FATAL: Account plugin missing required env vars: %s", strings.Join(missing, ", "))
	}
	if !strings.HasPrefix(c.DashboardURL, "https://") {
		if os.Getenv("ORBITPORT_ACCOUNT_ALLOW_INSECURE") != "true" {
			return fmt.Errorf("ORBITPORT_ACCOUNT_DASHBOARD_URL must be https; set ORBITPORT_ACCOUNT_ALLOW_INSECURE=true to override (e.g. local dev)")
		}
		utils.GetLogger("orbitport:account:config").Warnf(
			"ORBITPORT_ACCOUNT_ALLOW_INSECURE=true: dashboard URL is %s — M2M bearer token will be sent over plaintext HTTP, never enable in production",
			c.DashboardURL,
		)
	}
	if c.CreditsPerUnit == 0 {
		return fmt.Errorf("ORBITPORT_ACCOUNT_CREDITS_PER_UNIT must be > 0")
	}
	if c.HTTPTimeoutSecs <= 0 {
		return fmt.Errorf("ORBITPORT_ACCOUNT_HTTP_TIMEOUT_SECS must be > 0")
	}
	return nil
}

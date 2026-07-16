package auth

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// authConfig is the configuration for the Auth0 plugin.
type authConfig struct {
	// Auth0Domain is the domain of the Auth0 instance.
	Auth0Domain string
	// Auth0Audience is the audience of the Auth0 instance.
	Auth0Audience string
	// PatIss is the expected iss claim of PATs. Setting it (together with
	// PatIssuerPlugin) enables the PAT dual-validation path.
	PatIss string
	// PatAudience is the expected aud claim of PATs. Defaults to
	// Auth0Audience when unset.
	PatAudience string
	// PatIssuerPlugin is the gRPC URL of the issuer plugin, used to fetch
	// the JWKS PATs are verified against.
	PatIssuerPlugin string
}

func readFromEnv() *authConfig {
	setDefaults()

	return &authConfig{
		Auth0Domain:     viper.GetString("AUTH0_DOMAIN"),
		Auth0Audience:   viper.GetString("AUTH0_AUDIENCE"),
		PatIss:          strings.TrimSpace(viper.GetString("AUTH_PAT_ISS")),
		PatAudience:     strings.TrimSpace(viper.GetString("AUTH_PAT_AUDIENCE")),
		PatIssuerPlugin: strings.TrimSpace(viper.GetString("AUTH_ISSUER_PLUGIN")),
	}
}

func setDefaults() {
	viper.SetDefault("AUTH0_DOMAIN", "")
	viper.SetDefault("AUTH0_AUDIENCE", "")
	viper.SetDefault("AUTH_PAT_ISS", "")
	viper.SetDefault("AUTH_PAT_AUDIENCE", "")
	viper.SetDefault("AUTH_ISSUER_PLUGIN", "")
}

// patEnabled reports whether any PAT env var is set at all.
func (c *authConfig) patEnabled() bool {
	return c.PatIss != "" || c.PatAudience != "" || c.PatIssuerPlugin != ""
}

// validatePat refuses startup when the PAT config is partial. Fail-closed:
// either all required PAT vars are set, or none are.
func (c *authConfig) validatePat() error {
	if !c.patEnabled() {
		return nil
	}
	missing := []string{}
	if c.PatIss == "" {
		missing = append(missing, "ORBITPORT_AUTH_PAT_ISS")
	}
	if c.PatIssuerPlugin == "" {
		missing = append(missing, "ORBITPORT_AUTH_ISSUER_PLUGIN")
	}
	if len(missing) > 0 {
		return fmt.Errorf("FATAL: PAT validation partially configured, missing: %s", strings.Join(missing, ", "))
	}
	return nil
}

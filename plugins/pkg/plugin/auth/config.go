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
	// PatIss is the expected iss claim of PATs.
	PatIss string
	// PatAudience is the expected aud claim of PATs, defaulting to Auth0Audience.
	PatAudience string
	// PatIssuerPlugin is the gRPC URL of the patissuer plugin.
	PatIssuerPlugin string
	// ServiceClientIDs is the comma-separated Auth0 M2M client allowlist for
	// gateway-internal capability routes. Empty authorizes no service clients.
	ServiceClientIDs string
}

func readFromEnv() *authConfig {
	setDefaults()

	return &authConfig{
		Auth0Domain:      viper.GetString("AUTH0_DOMAIN"),
		Auth0Audience:    viper.GetString("AUTH0_AUDIENCE"),
		PatIss:           strings.TrimSpace(viper.GetString("AUTH_PAT_ISS")),
		PatAudience:      strings.TrimSpace(viper.GetString("AUTH_PAT_AUDIENCE")),
		PatIssuerPlugin:  strings.TrimSpace(viper.GetString("AUTH_PATISSUER_PLUGIN")),
		ServiceClientIDs: strings.TrimSpace(viper.GetString("AUTH_SERVICE_CLIENT_IDS")),
	}
}

func setDefaults() {
	viper.SetDefault("AUTH0_DOMAIN", "")
	viper.SetDefault("AUTH0_AUDIENCE", "")
	viper.SetDefault("AUTH_PAT_ISS", "")
	viper.SetDefault("AUTH_PAT_AUDIENCE", "")
	viper.SetDefault("AUTH_PATISSUER_PLUGIN", "")
	viper.SetDefault("AUTH_SERVICE_CLIENT_IDS", "")
}

// patEnabled reports whether any PAT env var is set at all.
func (c *authConfig) patEnabled() bool {
	return c.PatIss != "" || c.PatAudience != "" || c.PatIssuerPlugin != ""
}

// validatePat refuses startup when the PAT config is partial.
func (c *authConfig) validatePat() error {
	if !c.patEnabled() {
		return nil
	}
	missing := []string{}
	if c.PatIss == "" {
		missing = append(missing, "ORBITPORT_AUTH_PAT_ISS")
	}
	if c.PatIssuerPlugin == "" {
		missing = append(missing, "ORBITPORT_AUTH_PATISSUER_PLUGIN")
	}
	if len(missing) > 0 {
		return fmt.Errorf("FATAL: PAT validation partially configured, missing: %s", strings.Join(missing, ", "))
	}
	return nil
}

func (c *authConfig) serviceClientIDSet() map[string]struct{} {
	clientIDs := make(map[string]struct{})
	for _, clientID := range strings.Split(c.ServiceClientIDs, ",") {
		if clientID = strings.TrimSpace(clientID); clientID != "" {
			clientIDs[clientID] = struct{}{}
		}
	}
	return clientIDs
}

package jwks

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// jwksConfig is the configuration for the JWKS plugin.
type jwksConfig struct {
	// IssuerPlugin is the issuer plugin's gRPC address. Required. Without it
	// there is nothing to publish, and serving an empty key set would make
	// every verifier reject every PAT.
	IssuerPlugin string
	// HTTPPort serves the public key set. This is the only listener in the
	// platform that is meant to be internet-reachable besides the gateway.
	HTTPPort uint16
	// CacheTTLSecs bounds how often an anonymous request reaches the issuer.
	CacheTTLSecs int
	// TimeoutSecs bounds a single GetJwks call.
	TimeoutSecs int
}

func readFromEnv() *jwksConfig {
	setDefaults()

	return &jwksConfig{
		IssuerPlugin: strings.TrimSpace(viper.GetString("JWKS_ISSUER_PLUGIN")),
		HTTPPort:     viper.GetUint16("JWKS_HTTP_PORT"),
		CacheTTLSecs: viper.GetInt("JWKS_CACHE_TTL_SECS"),
		TimeoutSecs:  viper.GetInt("JWKS_TIMEOUT_SECS"),
	}
}

func setDefaults() {
	viper.SetDefault("JWKS_ISSUER_PLUGIN", "")
	viper.SetDefault("JWKS_HTTP_PORT", 8080)
	viper.SetDefault("JWKS_CACHE_TTL_SECS", 60)
	viper.SetDefault("JWKS_TIMEOUT_SECS", 5)
}

func (c *jwksConfig) validate() error {
	if c.IssuerPlugin == "" {
		return fmt.Errorf("FATAL: ORBITPORT_JWKS_ISSUER_PLUGIN is required")
	}
	if c.HTTPPort == 0 {
		return fmt.Errorf("FATAL: ORBITPORT_JWKS_HTTP_PORT must be non-zero")
	}
	if c.CacheTTLSecs < 0 {
		return fmt.Errorf("FATAL: ORBITPORT_JWKS_CACHE_TTL_SECS must not be negative")
	}
	if c.TimeoutSecs <= 0 {
		return fmt.Errorf("FATAL: ORBITPORT_JWKS_TIMEOUT_SECS must be positive")
	}
	return nil
}

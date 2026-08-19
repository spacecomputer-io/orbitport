package jwks

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// jwksConfig is the configuration for the JWKS plugin.
type jwksConfig struct {
	// Required. Without it there is nothing to publish, and an empty key set
	// would make every verifier reject every PAT.
	IssuerPlugin string
	// The only listener here meant to be internet-reachable.
	HTTPPort uint16
	// Bounds how often an anonymous request reaches the issuer.
	CacheTTLSecs int
	TimeoutSecs  int
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

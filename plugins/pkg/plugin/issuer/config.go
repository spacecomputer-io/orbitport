package issuer

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

const (
	signerLocal   = "local"
	signerTransit = "transit"
)

// issuerConfig is the configuration for the Issuer plugin.
type issuerConfig struct {
	Issuer   string
	Audience string
	Signer   string
	// Empty = generate an ephemeral key at startup, invalidating every
	// outstanding PAT on restart.
	LocalKeyPEM     string
	MaxTTLDays      int
	OpenBaoProxyURL string
	TransitMount    string
	TransitKey      string
	TimeoutSecs     int
}

func trimValue(value string) string {
	return strings.TrimSpace(value)
}

func readFromEnv() *issuerConfig {
	setDefaults()

	return &issuerConfig{
		Issuer:          trimValue(viper.GetString("ISSUER_ISS")),
		Audience:        trimValue(viper.GetString("ISSUER_AUD")),
		Signer:          trimValue(viper.GetString("ISSUER_SIGNER")),
		LocalKeyPEM:     viper.GetString("ISSUER_LOCAL_KEY_PEM"),
		MaxTTLDays:      viper.GetInt("ISSUER_MAX_TTL_DAYS"),
		OpenBaoProxyURL: trimValue(viper.GetString("ISSUER_OPENBAO_PROXY_URL")),
		TransitMount:    trimValue(viper.GetString("ISSUER_TRANSIT_MOUNT")),
		TransitKey:      trimValue(viper.GetString("ISSUER_TRANSIT_KEY")),
		TimeoutSecs:     viper.GetInt("ISSUER_TIMEOUT_SECS"),
	}
}

func setDefaults() {
	viper.SetDefault("ISSUER_ISS", "")
	viper.SetDefault("ISSUER_AUD", "")
	viper.SetDefault("ISSUER_SIGNER", signerLocal)
	viper.SetDefault("ISSUER_LOCAL_KEY_PEM", "")
	viper.SetDefault("ISSUER_MAX_TTL_DAYS", 370)
	viper.SetDefault("ISSUER_OPENBAO_PROXY_URL", "")
	viper.SetDefault("ISSUER_TRANSIT_MOUNT", "transit")
	viper.SetDefault("ISSUER_TRANSIT_KEY", "pat-signing")
	viper.SetDefault("ISSUER_TIMEOUT_SECS", 10)
}

// validate refuses startup when required vars are missing. Fail-closed.
func (c *issuerConfig) validate() error {
	missing := []string{}
	if c.Issuer == "" {
		missing = append(missing, "ORBITPORT_ISSUER_ISS")
	}
	if c.Audience == "" {
		missing = append(missing, "ORBITPORT_ISSUER_AUD")
	}
	if len(missing) > 0 {
		return fmt.Errorf("FATAL: Issuer plugin missing required env vars: %s", strings.Join(missing, ", "))
	}
	if c.Signer != signerLocal && c.Signer != signerTransit {
		return fmt.Errorf("ORBITPORT_ISSUER_SIGNER must be %q or %q, got %q", signerLocal, signerTransit, c.Signer)
	}
	if c.Signer == signerTransit {
		if c.OpenBaoProxyURL == "" {
			return fmt.Errorf("FATAL: ORBITPORT_ISSUER_OPENBAO_PROXY_URL is required when ORBITPORT_ISSUER_SIGNER=transit")
		}
		if c.TransitMount == "" || c.TransitKey == "" {
			return fmt.Errorf("ORBITPORT_ISSUER_TRANSIT_MOUNT and ORBITPORT_ISSUER_TRANSIT_KEY must be non-empty")
		}
		if c.TimeoutSecs <= 0 {
			return fmt.Errorf("ORBITPORT_ISSUER_TIMEOUT_SECS must be > 0")
		}
	}
	if c.MaxTTLDays <= 0 {
		return fmt.Errorf("ORBITPORT_ISSUER_MAX_TTL_DAYS must be > 0")
	}
	return nil
}

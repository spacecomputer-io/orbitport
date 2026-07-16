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
	// Issuer is the iss claim stamped into every PAT and the value
	// verifiers route on during the dual-validation window.
	Issuer string
	// Audience is the aud claim (same role as AUTH0_AUDIENCE today).
	Audience string
	// Signer selects key custody: "local" (in-process EC P-256 key, dev
	// and pre-OpenBao environments) or "transit" (OpenBao Transit —
	// not implemented yet).
	Signer string
	// LocalKeyPEM is a PKCS#8 or SEC1 PEM-encoded EC P-256 private key
	// for the local signer. Empty = generate an ephemeral key at startup
	// (dev only: every restart invalidates all outstanding PATs).
	LocalKeyPEM string
	// MaxTTLDays caps how far in the future expires_at may be. Backstop
	// against a buggy caller minting effectively-eternal tokens; the
	// dashboard enforces the real product cap (D6).
	MaxTTLDays int
}

func trimValue(value string) string {
	return strings.TrimSpace(value)
}

func readFromEnv() *issuerConfig {
	setDefaults()

	return &issuerConfig{
		Issuer:      trimValue(viper.GetString("ISSUER_ISS")),
		Audience:    trimValue(viper.GetString("ISSUER_AUD")),
		Signer:      trimValue(viper.GetString("ISSUER_SIGNER")),
		LocalKeyPEM: viper.GetString("ISSUER_LOCAL_KEY_PEM"),
		MaxTTLDays:  viper.GetInt("ISSUER_MAX_TTL_DAYS"),
	}
}

func setDefaults() {
	viper.SetDefault("ISSUER_ISS", "")
	viper.SetDefault("ISSUER_AUD", "")
	viper.SetDefault("ISSUER_SIGNER", signerLocal)
	viper.SetDefault("ISSUER_LOCAL_KEY_PEM", "")
	viper.SetDefault("ISSUER_MAX_TTL_DAYS", 370)
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
	if c.MaxTTLDays <= 0 {
		return fmt.Errorf("ORBITPORT_ISSUER_MAX_TTL_DAYS must be > 0")
	}
	return nil
}

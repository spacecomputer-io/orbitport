package crypto2

import (
	"os"
	"strings"

	"github.com/spf13/viper"
)

// config is the configuration for the Crypto2 plugin.
type config struct {
	// APIURL is the URL of the Crypto2 satellite API.
	APIURL string
	// AuthURL is the OAuth2 token endpoint for the Crypto2 satellite API.
	AuthURL string
	// ClientID is the OAuth client ID for the Crypto2 satellite API.
	ClientID string
	// ClientSecret is the OAuth client secret for the Crypto2 satellite API.
	ClientSecret string
	// RateLimit is the rate limit for the Crypto2 satellite API.
	RateLimit float64
	// Timeout is the timeout in seconds for Crypto2 HTTP requests.
	Timeout int
}

func trimValue(value string) string {
	return strings.TrimSpace(value)
}

func applyLegacyEnvAlias(canonicalKey, legacyKey string) {
	canonicalEnv := "ORBITPORT_" + canonicalKey
	legacyEnv := "ORBITPORT_" + legacyKey
	if _, ok := os.LookupEnv(canonicalEnv); ok {
		return
	}
	if value, ok := os.LookupEnv(legacyEnv); ok {
		viper.Set(canonicalKey, value)
	}
}

func applyLegacyEnvAliases() {
	applyLegacyEnvAlias("CRYPTO2_API_URL", "APTOS_ORBITAL_API_URL")
	applyLegacyEnvAlias("CRYPTO2_AUTH_URL", "APTOS_ORBITAL_AUTH_URL")
	applyLegacyEnvAlias("CRYPTO2_CLIENT_ID", "APTOS_ORBITAL_CLIENT_ID")
	applyLegacyEnvAlias("CRYPTO2_CLIENT_SECRET", "APTOS_ORBITAL_CLIENT_SECRET")
	applyLegacyEnvAlias("CRYPTO2_RATE_LIMIT", "APTOS_ORBITAL_RATE_LIMIT")
	applyLegacyEnvAlias("CRYPTO2_TIMEOUT", "APTOS_ORBITAL_TIMEOUT")
}

func readFromEnv() *config {
	setDefaults()
	applyLegacyEnvAliases()

	return &config{
		APIURL:       trimValue(viper.GetString("CRYPTO2_API_URL")),
		AuthURL:      trimValue(viper.GetString("CRYPTO2_AUTH_URL")),
		ClientID:     trimValue(viper.GetString("CRYPTO2_CLIENT_ID")),
		ClientSecret: trimValue(viper.GetString("CRYPTO2_CLIENT_SECRET")),
		RateLimit:    viper.GetFloat64("CRYPTO2_RATE_LIMIT"),
		Timeout:      viper.GetInt("CRYPTO2_TIMEOUT"),
	}
}

func setDefaults() {
	viper.SetDefault("CRYPTO2_API_URL", DefaultAPIURL)
	viper.SetDefault("CRYPTO2_AUTH_URL", DefaultAuthURL)
	viper.SetDefault("CRYPTO2_CLIENT_ID", "")
	viper.SetDefault("CRYPTO2_CLIENT_SECRET", "")
	viper.SetDefault("CRYPTO2_RATE_LIMIT", 0.5)
	viper.SetDefault("CRYPTO2_TIMEOUT", 20)
}

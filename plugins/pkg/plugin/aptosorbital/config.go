package aptosorbital

import (
	"strings"

	"github.com/spf13/viper"
)

// aptosOrbitalConfig is the configuration for the Aptos Orbital plugin.
type aptosOrbitalConfig struct {
	// AptosOrbitalApiUrl is the URL of the Aptos Orbital API.
	AptosOrbitalApiUrl string
	// AptosOrbitalAuthUrl is the URL of the Aptos Orbital oauth2 token endpoint.
	AptosOrbitalAuthUrl string
	// AptosOrbitalClientId is the client ID for the Aptos Orbital API.
	AptosOrbitalClientId string
	// AptosOrbitalClientSecret is the client secret for the Aptos Orbital API.
	AptosOrbitalClientSecret string
	// AptosOrbitalRateLimit is the rate limit for the Aptos Orbital API.
	AptosOrbitalRateLimit float64
}

func trimValue(value string) string {
	return strings.TrimSpace(value)
}

func readFromEnv() *aptosOrbitalConfig {
	setDefaults()

	return &aptosOrbitalConfig{
		AptosOrbitalApiUrl:       trimValue(viper.GetString("APTOS_ORBITAL_API_URL")),
		AptosOrbitalAuthUrl:      trimValue(viper.GetString("APTOS_ORBITAL_AUTH_URL")),
		AptosOrbitalClientId:     trimValue(viper.GetString("APTOS_ORBITAL_CLIENT_ID")),
		AptosOrbitalClientSecret: trimValue(viper.GetString("APTOS_ORBITAL_CLIENT_SECRET")),
		AptosOrbitalRateLimit:    viper.GetFloat64("APTOS_ORBITAL_RATE_LIMIT"),
	}
}

func setDefaults() {
	viper.SetDefault("APTOS_ORBITAL_API_URL", "https://api.aptosorbital.com")
	viper.SetDefault("APTOS_ORBITAL_AUTH_URL", "https://auth.aptosorbital.com/oauth2/token")
	viper.SetDefault("APTOS_ORBITAL_CLIENT_ID", "")
	viper.SetDefault("APTOS_ORBITAL_CLIENT_SECRET", "")
	viper.SetDefault("APTOS_ORBITAL_RATE_LIMIT", 0.5)
}

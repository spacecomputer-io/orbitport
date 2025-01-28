package config

import (
	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

type Config struct {
	// Port is the port the gateway listens on.
	Port uint16
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

func ReadFromEnv() *Config {
	_ = godotenv.Load()
	viper.SetEnvPrefix("STARGATE") // Will read env vars like STARGATE_VARNAME
	viper.AutomaticEnv()           // Read in environment variables that match

	setDefaults()

	return &Config{
		Port:                     viper.GetUint16("PORT"),
		AptosOrbitalApiUrl:       viper.GetString("APTOS_ORBITAL_API_URL"),
		AptosOrbitalAuthUrl:      viper.GetString("APTOS_ORBITAL_AUTH_URL"),
		AptosOrbitalClientId:     viper.GetString("APTOS_ORBITAL_CLIENT_ID"),
		AptosOrbitalClientSecret: viper.GetString("APTOS_ORBITAL_CLIENT_SECRET"),
		AptosOrbitalRateLimit:    viper.GetFloat64("APTOS_ORBITAL_RATE_LIMIT"),
	}
}

func setDefaults() {
	viper.SetDefault("PORT", 8080)
	viper.SetDefault("APTOS_ORBITAL_API_URL", "https://api.aptosorbital.com")
	viper.SetDefault("APTOS_ORBITAL_AUTH_URL", "https://auth.aptosorbital.com/oauth2/token")
	viper.SetDefault("APTOS_ORBITAL_CLIENT_ID", "")
	viper.SetDefault("APTOS_ORBITAL_CLIENT_SECRET", "")
	viper.SetDefault("APTOS_ORBITAL_RATE_LIMIT", 0.1)
}

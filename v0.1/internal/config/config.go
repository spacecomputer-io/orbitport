package config

import (
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

type Config struct {
	Proxies []string
	// Port is the port the gateway listens on.
	Port uint16
	// MetricsPort is the port the metrics server listens on.
	MetricsPort uint16
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
	// StaticAuthToken is a static auth token for the gateway, used mostly in tests.
	StaticAuthToken string
	// Auth0Domain is the domain of the Auth0 instance.
	Auth0Domain string
	// Auth0Audience is the audience of the Auth0 instance.
	Auth0Audience string
	// MasterSeedInterval is the period for fetching the new master seed.
	MasterSeedInterval time.Duration
	// DefaultMasterSeed is the default master seed to use.
	DefaultMasterSeed string
}

func ReadFromEnv() *Config {
	_ = godotenv.Load()
	viper.SetEnvPrefix("ORBITPORT") // Will read env vars like ORBITPORT_VARNAME
	viper.AutomaticEnv()            // Read in environment variables that match

	setDefaults()

	return &Config{
		Proxies:                  viper.GetStringSlice("PROXIES"),
		Port:                     viper.GetUint16("PORT"),
		MetricsPort:              viper.GetUint16("METRICS_PORT"),
		AptosOrbitalApiUrl:       viper.GetString("APTOS_ORBITAL_API_URL"),
		AptosOrbitalAuthUrl:      viper.GetString("APTOS_ORBITAL_AUTH_URL"),
		AptosOrbitalClientId:     viper.GetString("APTOS_ORBITAL_CLIENT_ID"),
		AptosOrbitalClientSecret: viper.GetString("APTOS_ORBITAL_CLIENT_SECRET"),
		AptosOrbitalRateLimit:    viper.GetFloat64("APTOS_ORBITAL_RATE_LIMIT"),
		StaticAuthToken:          viper.GetString("STATIC_AUTH_TOKEN"),
		Auth0Domain:              viper.GetString("AUTH0_DOMAIN"),
		Auth0Audience:            viper.GetString("AUTH0_AUDIENCE"),
		MasterSeedInterval:       viper.GetDuration("MASTER_SEED_INTERVAL"),
		DefaultMasterSeed:        viper.GetString("DEFAULT_MASTER_SEED"),
	}
}

func setDefaults() {
	viper.SetDefault("PROXIES", []string{})
	viper.SetDefault("PORT", 8080)
	viper.SetDefault("METRICS_PORT", 8081)
	viper.SetDefault("APTOS_ORBITAL_API_URL", "https://api.aptosorbital.com")
	viper.SetDefault("APTOS_ORBITAL_AUTH_URL", "https://auth.aptosorbital.com/oauth2/token")
	viper.SetDefault("APTOS_ORBITAL_CLIENT_ID", "")
	viper.SetDefault("APTOS_ORBITAL_CLIENT_SECRET", "")
	viper.SetDefault("APTOS_ORBITAL_RATE_LIMIT", 0.5)
	viper.SetDefault("STATIC_AUTH_TOKEN", "")
	viper.SetDefault("AUTH0_DOMAIN", "")
	viper.SetDefault("AUTH0_AUDIENCE", "")
	viper.SetDefault("MASTER_SEED_INTERVAL", "1h")
	viper.SetDefault("DEFAULT_MASTER_SEED", "")
}

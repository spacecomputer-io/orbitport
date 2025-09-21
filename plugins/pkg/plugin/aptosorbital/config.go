package aptosorbital

import (
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
	// AptosOrbitalDefaultMasterSeed is the default master seed for testing and for complete connectivity failure fallback
	AptosOrbitalDefaultMasterSeed string
	// AptosOrbitalTRNGSize is the expected size of each cTRNGN
	AptosOrbitalTRNGSize int
	// AptosOrbitalMaxMasterSeeds is the maximum number of master seeds that will be kept in the ring buffer
	AptosOrbitalMaxMasterSeeds int
	// AptosOrbitalSeedPeriod is the interval of time that must pass before a new master seed will be fetched from aptos orbital
	AptosOrbitalSeedPeriod int64
}

func readFromEnv() *aptosOrbitalConfig {
	setDefaults()

	return &aptosOrbitalConfig{
		AptosOrbitalApiUrl:            viper.GetString("APTOS_ORBITAL_API_URL"),
		AptosOrbitalAuthUrl:           viper.GetString("APTOS_ORBITAL_AUTH_URL"),
		AptosOrbitalClientId:          viper.GetString("APTOS_ORBITAL_CLIENT_ID"),
		AptosOrbitalClientSecret:      viper.GetString("APTOS_ORBITAL_CLIENT_SECRET"),
		AptosOrbitalRateLimit:         viper.GetFloat64("APTOS_ORBITAL_RATE_LIMIT"),
		AptosOrbitalDefaultMasterSeed: viper.GetString("APTOS_ORBITAL_DEFAULT_MASTER_SEED"),
		AptosOrbitalTRNGSize:          viper.GetInt("APTOS_ORBITAL_TRNG_SIZE"),
		AptosOrbitalMaxMasterSeeds:    viper.GetInt("APTOS_ORBITAL_MAX_MASTER_SEEDS"),
		AptosOrbitalSeedPeriod:        viper.GetInt64("APTOS_ORBITAL_SEED_PERIOD"),
	}
}

func setDefaults() {
	viper.SetDefault("APTOS_ORBITAL_API_URL", "https://api.aptosorbital.com")
	viper.SetDefault("APTOS_ORBITAL_AUTH_URL", "https://auth.aptosorbital.com/oauth2/token")
	viper.SetDefault("APTOS_ORBITAL_CLIENT_ID", "")
	viper.SetDefault("APTOS_ORBITAL_CLIENT_SECRET", "")
	viper.SetDefault("APTOS_ORBITAL_RATE_LIMIT", 0.5)
	viper.SetDefault("APTOS_ORBITAL_DEFAULT_MASTER_SEED", "288ae5323d7a34ada0fb29962cfdc9d5ce4bb2bcdb4b0f137a464d9bd6ceb982")
	viper.SetDefault("APTOS_ORBITAL_TRNG_SIZE", 32)
	viper.SetDefault("APTOS_ORBITAL_MAX_MASTER_SEEDS", 10)
	viper.SetDefault("APTOS_ORBITAL_SEED_PERIOD", 3600)
}

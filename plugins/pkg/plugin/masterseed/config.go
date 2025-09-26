package masterseed

import (
	"github.com/spf13/viper"
)

// aptosOrbitalConfig is the configuration for the Aptos Orbital plugin.
type masterSeedConfig struct {
	// MasterSeedDefaultMasterSeed is the default master seed for testing and for complete connectivity failure fallback
	MasterSeedDefaultMasterSeed string
	// MasterSeedTRNGSize is the expected size of each cTRNGN
	MasterSeedTRNGSize int
	// MasterSeedMaxMasterSeeds is the maximum number of master seeds that will be kept in the ring buffer
	MasterSeedMaxMasterSeeds int
	// MaserSeedPeriod is the interval of time that must pass before a new master seed will be fetched from aptos orbital
	MaserSeedPeriod int64
	AptosPlugin     string `json:"aptos_plugin"`
}

func readFromEnv() *masterSeedConfig {
	setDefaults()

	return &masterSeedConfig{
		MasterSeedDefaultMasterSeed: viper.GetString("MASTER_SEED_DEFAULT_MASTER_SEED"),
		MasterSeedTRNGSize:          viper.GetInt("MASTER_SEED_TRNG_SIZE"),
		MasterSeedMaxMasterSeeds:    viper.GetInt("MASTER_SEED_MAX_MASTER_SEEDS"),
		MaserSeedPeriod:             viper.GetInt64("MASTER_SEED_SEED_PERIOD"),
		AptosPlugin:                 viper.GetString("APTOS_PLUGIN"),
	}
}

func setDefaults() {
	viper.SetDefault("MASTER_SEED_DEFAULT_MASTER_SEED", "288ae5323d7a34ada0fb29962cfdc9d5ce4bb2bcdb4b0f137a464d9bd6ceb982")
	viper.SetDefault("MASTER_SEED_TRNG_SIZE", 32)
	viper.SetDefault("MASTER_SEED_MAX_MASTER_SEEDS", 10)
	viper.SetDefault("MASTER_SEED_SEED_PERIOD", 3600)
	viper.SetDefault("APTOS_PLUGIN", "plugin-aptos-orbital:50001")
}

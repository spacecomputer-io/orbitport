package masterseed

import (
	"os"
	"strings"

	"github.com/spf13/viper"
)

// masterSeedConfig is the configuration for the masterseed plugin.
type masterSeedConfig struct {
	// MasterSeedDefaultMasterSeeds is an array of  default master seeds complete connectivity failure fallback and cold-start
	MasterSeedDefaultMasterSeeds []string
	// MasterSeedTRNGSize is the expected size of each cTRNGN
	MasterSeedTRNGSize int
	// MasterSeedMaxMasterSeeds is the maximum number of master seeds that will be kept in the ring buffer
	MasterSeedMaxMasterSeeds int
	// MaserSeedPeriod is the interval of time that must pass before a new master seed will be fetched from crypto2
	MaserSeedPeriod              int64
	Crypto2Plugin                string `json:"crypto2_plugin"`
	MasterSeedMaxCountPerRequest int
}

func extractSeeds() []string {
	rawSeeds := strings.TrimSpace(viper.GetString("DEFAULT_MASTER_SEEDS"))
	var seeds []string
	if rawSeeds != "" {
		parts := strings.Split(rawSeeds, ",")
		for _, s := range parts {
			cleaned := strings.TrimSpace(s)
			if cleaned != "" {
				seeds = append(seeds, cleaned)
			}
		}
	}
	return seeds
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

func readFromEnv() *masterSeedConfig {
	setDefaults()
	applyLegacyEnvAlias("CRYPTO2_PLUGIN", "APTOS_PLUGIN")

	seeds := extractSeeds()

	return &masterSeedConfig{
		MasterSeedDefaultMasterSeeds: seeds,
		MasterSeedTRNGSize:           viper.GetInt("MASTER_SEED_TRNG_SIZE"),
		MasterSeedMaxMasterSeeds:     viper.GetInt("MASTER_SEED_MAX_MASTER_SEEDS"),
		MaserSeedPeriod:              viper.GetInt64("MASTER_SEED_SEED_PERIOD"),
		Crypto2Plugin:                viper.GetString("CRYPTO2_PLUGIN"),
		MasterSeedMaxCountPerRequest: viper.GetInt("MASTER_SEED_MAX_COUNT_PER_REQUEST"),
	}
}

func setDefaults() {
	viper.SetDefault("DEFAULT_MASTER_SEEDS", "")
	viper.SetDefault("MASTER_SEED_TRNG_SIZE", 32)
	viper.SetDefault("MASTER_SEED_MAX_MASTER_SEEDS", 100)
	viper.SetDefault("MASTER_SEED_SEED_PERIOD", 3600)
	viper.SetDefault("CRYPTO2_PLUGIN", "plugin-crypto2:50001")
	viper.SetDefault("MASTER_SEED_MAX_COUNT_PER_REQUEST", 25000)
}

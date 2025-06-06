package ipfs

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	IPFSAddress   string        `json:"ipfs_address"`
	CacheSize     uint          `json:"cache_size"`
	LeaseDuration time.Duration `json:"lease_duration"`
}

func readFromEnv() *Config {
	setDefaults()

	return &Config{
		IPFSAddress:   viper.GetString("IPFS_ADDRESS"),
		CacheSize:     viper.GetUint("PLUGIN_CACHE_SIZE"),
		LeaseDuration: viper.GetDuration("IPNS_LEASE_DURATION"),
	}
}

func setDefaults() {
	viper.SetDefault("IPFS_ADDRESS", "http://localhost:5001")
	viper.SetDefault("PLUGIN_CACHE_SIZE", 100)
	viper.SetDefault("IPNS_LEASE_DURATION", time.Hour*24)
}

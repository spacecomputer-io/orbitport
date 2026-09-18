package ipfs

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	IPFSAddress   string        `json:"ipfs_address"`
	CacheSize     uint          `json:"cache_size"`
	LeaseDuration time.Duration `json:"lease_duration"`
	MaxAddBytes   uint          `json:"max_add_bytes"`
	MaxGetBytes   uint          `json:"max_get_bytes"`
}

func readFromEnv() *Config {
	setDefaults()

	return &Config{
		IPFSAddress:   viper.GetString("IPFS_ADDRESS"),
		CacheSize:     viper.GetUint("PLUGIN_CACHE_SIZE"),
		LeaseDuration: viper.GetDuration("IPNS_LEASE_DURATION"),
		MaxAddBytes:   viper.GetUint("PLUGIN_MAX_ADD_BYTES"),
		MaxGetBytes:   viper.GetUint("PLUGIN_MAX_GET_BYTES"),
	}
}

func setDefaults() {
	viper.SetDefault("IPFS_ADDRESS", "http://localhost:5001")
	viper.SetDefault("PLUGIN_CACHE_SIZE", 100)
	viper.SetDefault("IPNS_LEASE_DURATION", time.Hour*24)
	viper.SetDefault("PLUGIN_MAX_ADD_BYTES", 1048576)
	viper.SetDefault("PLUGIN_MAX_GET_BYTES", 1048576)
}

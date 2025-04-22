package ipfs

import (
	"github.com/spf13/viper"
)

type Config struct {
	IPFSAddress string `json:"ipfs_address"`
	CacheSize   int    `json:"cache_size"`
}

func readFromEnv() *Config {
	setDefaults()

	return &Config{
		IPFSAddress: viper.GetString("ORBITPORT_IPFS_ADDRESS"),
		CacheSize:   viper.GetInt("ORBITPORT_IPFS_AGENT_CACHE_SIZE"),
	}
}

func setDefaults() {
	viper.SetDefault("ORBITPORT_IPFS_ADDRESS", "http://localhost:5001")
	viper.SetDefault("ORBITPORT_IPFS_AGENT_CACHE_SIZE", 100)
}

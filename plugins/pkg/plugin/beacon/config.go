package beacon

import (
	"github.com/spf13/viper"
)

type Config struct {
	IPFSPlugin     string `json:"ipfs_plugin"`
	CTRNGPlugin    string `json:"ctrng_plugin"`
	BeaconRegistry string `json:"beacon_registry"`
	BeaconMsg      string `json:"beacon_msg"`
	IPFSAddress    string `json:"ipfs_address"`
}

func readFromEnv() Config {
	setDefaults()

	return Config{
		IPFSPlugin:     viper.GetString("IPFS_PLUGIN"),
		CTRNGPlugin:    viper.GetString("CTRNG_PLUGIN"),
		BeaconRegistry: viper.GetString("BEACON_REGISTRY"),
		BeaconMsg:      viper.GetString("BEACON_MSG"),
		IPFSAddress:    viper.GetString("IPFS_ADDRESS"),
	}
}

func setDefaults() {
	viper.SetDefault("ORBITPORT_IPFS_PLUGIN", "plugin-ipfs:50002")
	viper.SetDefault("ORBITPORT_CTRNG_PLUGIN", "plugin-aptos-orbital:50001")
	viper.SetDefault("BEACON_REGISTRY", "")
	viper.SetDefault("BEACON_MSG", "Rm9ydHVuZQrotKLlr4wK157Xltec")
	viper.SetDefault("IPFS_ADDRESS", "http://ipfs-node:5001")
}

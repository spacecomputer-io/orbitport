package beacon

import (
	"github.com/spf13/viper"
)

type Config struct {
	IPFSPlugin     string `json:"ipfs_plugin"`
	CTRNGPlugin    string `json:"ctrng_plugin"`
	BeaconRegsitry string `json:"beacon_registry"`
}

func readFromEnv() Config {
	setDefaults()

	return Config{
		IPFSPlugin:     viper.GetString("IPFS_PLUGIN"),
		CTRNGPlugin:    viper.GetString("CTRNG_PLUGIN"),
		BeaconRegsitry: viper.GetString("BEACON_REGISTRY"),
	}
}

func setDefaults() {
	viper.SetDefault("ORBITPORT_IPFS_PLUGIN", "plugin-ipfs:50002")
	viper.SetDefault("ORBITPORT_CTRNG_PLUGIN", "plugin-aptos-orbital:50001")
	viper.SetDefault("BEACON_REGISTRY", "")
}

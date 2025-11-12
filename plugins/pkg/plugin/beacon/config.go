package beacon

import (
	"github.com/spf13/viper"
)

type Config struct {
	IPFSPlugin        string `json:"ipfs_plugin"`
	CTRNGPlugin       string `json:"ctrng_plugin"`
	MasterSeedPlugin  string `json:"masterseed_plugin"`
	BeaconRegistry    string `json:"beacon_registry"`
	DefaultBeaconName string `json:"default_beacon_name"`
	BeaconMsg         string `json:"beacon_msg"`
	BeaconInterval    int32  `json:"beacon_interval"`
	IPFSAddress       string `json:"ipfs_address"`
}

func readFromEnv() Config {
	setDefaults()

	return Config{
		IPFSPlugin:        viper.GetString("IPFS_PLUGIN"),
		CTRNGPlugin:       viper.GetString("CTRNG_PLUGIN"),
		MasterSeedPlugin:  viper.GetString("MASTERSEED_PLUGIN"),
		BeaconRegistry:    viper.GetString("BEACON_REGISTRY"),
		DefaultBeaconName: viper.GetString("DEFAULT_BEACON_NAME"),
		BeaconMsg:         viper.GetString("BEACON_MSG"),
		BeaconInterval:    viper.GetInt32("BEACON_UPDATE_INTERVAL"),
		IPFSAddress:       viper.GetString("IPFS_ADDRESS"),
	}
}

func setDefaults() {
	viper.SetDefault("ORBITPORT_IPFS_PLUGIN", "plugin-ipfs:50002")
	viper.SetDefault("ORBITPORT_CTRNG_PLUGIN", "plugin-aptos-orbital:50001")
	viper.SetDefault("ORBITPORT_MASTERSEED_PLUGIN", "plugin-masterseed:50003")
	viper.SetDefault("BEACON_REGISTRY", "orbitport-registry")
	viper.SetDefault("DEFAULT_BEACON_NAME", "randomness-beacon1.0")
	viper.SetDefault("BEACON_MSG", "Rm9ydHVuZQrotKLlr4wK157Xltec")
	viper.SetDefault("BEACON_UPDATE_INTERVAL", 60)
	viper.SetDefault("IPFS_ADDRESS", "http://ipfs-node:5001")
}

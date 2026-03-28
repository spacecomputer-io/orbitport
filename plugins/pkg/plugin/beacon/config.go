package beacon

import "github.com/spf13/viper"

type Config struct {
	IPFSPlugin               string `json:"ipfs_plugin"`
	CTRNGPlugin              string `json:"ctrng_plugin"`
	MasterSeedPlugin         string `json:"masterseed_plugin"`
	BeaconRegistry           string `json:"beacon_registry"`
	DefaultBeaconName        string `json:"default_beacon_name"`
	BeaconMsg                string `json:"beacon_msg"`
	BeaconInterval           int32  `json:"beacon_interval"`
	IPFSAddress              string `json:"ipfs_address"`
	RegistryRetrievalTimeout int32  `json:"registry_retrieval_timeout"`
	SchedulerTickInterval    int32  `json:"scheduler_tick_interval"`
	RetryBaseDelay           int32  `json:"retry_base_delay"`
	RetryMaxDelay            int32  `json:"retry_max_delay"`
	StaleRetryDelay          int32  `json:"stale_retry_delay"`
	HealthFailureThreshold   uint32 `json:"health_failure_threshold"`
}

func readFromEnv() Config {
	setDefaults()

	return Config{
		IPFSPlugin:               viper.GetString("IPFS_PLUGIN"),
		CTRNGPlugin:              viper.GetString("CTRNG_PLUGIN"),
		MasterSeedPlugin:         viper.GetString("MASTERSEED_PLUGIN"),
		BeaconRegistry:           viper.GetString("BEACON_REGISTRY"),
		DefaultBeaconName:        viper.GetString("DEFAULT_BEACON_NAME"),
		BeaconMsg:                viper.GetString("BEACON_MSG"),
		BeaconInterval:           viper.GetInt32("BEACON_UPDATE_INTERVAL"),
		IPFSAddress:              viper.GetString("IPFS_ADDRESS"),
		RegistryRetrievalTimeout: viper.GetInt32("REGISTRY_RETRIEVAL_TIMEOUT"),
		SchedulerTickInterval:    viper.GetInt32("SCHEDULER_TICK_INTERVAL"),
		RetryBaseDelay:           viper.GetInt32("RETRY_BASE_DELAY"),
		RetryMaxDelay:            viper.GetInt32("RETRY_MAX_DELAY"),
		StaleRetryDelay:          viper.GetInt32("STALE_RETRY_DELAY"),
		HealthFailureThreshold:   viper.GetUint32("HEALTH_FAILURE_THRESHOLD"),
	}
}

func setDefaults() {
	viper.SetDefault("IPFS_PLUGIN", "plugin-ipfs:50002")
	viper.SetDefault("CTRNG_PLUGIN", "plugin-aptos-orbital:50001")
	viper.SetDefault("MASTERSEED_PLUGIN", "plugin-masterseed:50003")
	viper.SetDefault("BEACON_REGISTRY", "orbitport-registry")
	viper.SetDefault("DEFAULT_BEACON_NAME", "randomness-beacon1.0")
	viper.SetDefault("BEACON_MSG", "Rm9ydHVuZQrotKLlr4wK157Xltec")
	viper.SetDefault("BEACON_UPDATE_INTERVAL", 60)
	viper.SetDefault("IPFS_ADDRESS", "http://ipfs-node:5001")
	viper.SetDefault("REGISTRY_RETRIEVAL_TIMEOUT", 90)
	viper.SetDefault("SCHEDULER_TICK_INTERVAL", 1)
	viper.SetDefault("RETRY_BASE_DELAY", 2)
	viper.SetDefault("RETRY_MAX_DELAY", 60)
	viper.SetDefault("STALE_RETRY_DELAY", 2)
	viper.SetDefault("HEALTH_FAILURE_THRESHOLD", 3)
}

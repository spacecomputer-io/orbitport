package kms

import "github.com/spf13/viper"

const (
	defaultKMSEthereumMount = "ethereum"
	defaultKMSPQCMount      = "pqc"
	defaultKMSTransitMount  = "transit"
	defaultKMSKVMount       = "secret"
	defaultKMSTimeoutSecs   = 10
)

type kmsConfig struct {
	OpenBaoProxyURL string
	EthereumMount   string
	PQCMount        string
	TransitMount    string
	KVMount         string
	CedarPolicyPath string
	TimeoutSecs     int
}

func readFromEnv() *kmsConfig {
	setDefaults()

	return &kmsConfig{
		OpenBaoProxyURL: viper.GetString("KMS_OPENBAO_PROXY_URL"),
		EthereumMount:   viper.GetString("KMS_ETHEREUM_MOUNT"),
		PQCMount:        viper.GetString("KMS_PQC_MOUNT"),
		TransitMount:    viper.GetString("KMS_TRANSIT_MOUNT"),
		KVMount:         viper.GetString("KMS_KV_MOUNT"),
		CedarPolicyPath: viper.GetString("KMS_CEDAR_POLICY_PATH"),
		TimeoutSecs:     viper.GetInt("KMS_TIMEOUT_SECS"),
	}
}

func setDefaults() {
	viper.SetDefault("KMS_ETHEREUM_MOUNT", defaultKMSEthereumMount)
	viper.SetDefault("KMS_PQC_MOUNT", defaultKMSPQCMount)
	viper.SetDefault("KMS_TRANSIT_MOUNT", defaultKMSTransitMount)
	viper.SetDefault("KMS_KV_MOUNT", defaultKMSKVMount)
	viper.SetDefault("KMS_CEDAR_POLICY_PATH", "")
	viper.SetDefault("KMS_TIMEOUT_SECS", defaultKMSTimeoutSecs)
}

func withKMSConfigDefaults(cfg *kmsConfig) *kmsConfig {
	if cfg == nil {
		cfg = &kmsConfig{}
	}
	next := *cfg
	if next.EthereumMount == "" {
		next.EthereumMount = defaultKMSEthereumMount
	}
	if next.PQCMount == "" {
		next.PQCMount = defaultKMSPQCMount
	}
	if next.TransitMount == "" {
		next.TransitMount = defaultKMSTransitMount
	}
	if next.KVMount == "" {
		next.KVMount = defaultKMSKVMount
	}
	if next.TimeoutSecs == 0 {
		next.TimeoutSecs = defaultKMSTimeoutSecs
	}
	return &next
}

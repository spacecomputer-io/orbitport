package kms

import "github.com/spf13/viper"

type kmsConfig struct {
	OpenBaoProxyURL string
	EthereumMount   string
	TransitMount    string
	KVMount         string
	TimeoutSecs     int
}

func readFromEnv() *kmsConfig {
	setDefaults()

	return &kmsConfig{
		OpenBaoProxyURL: viper.GetString("KMS_OPENBAO_PROXY_URL"),
		EthereumMount:   viper.GetString("KMS_ETHEREUM_MOUNT"),
		TransitMount:    viper.GetString("KMS_TRANSIT_MOUNT"),
		KVMount:         viper.GetString("KMS_KV_MOUNT"),
		TimeoutSecs:     viper.GetInt("KMS_TIMEOUT_SECS"),
	}
}

func setDefaults() {
	viper.SetDefault("KMS_ETHEREUM_MOUNT", "ethereum")
	viper.SetDefault("KMS_TRANSIT_MOUNT", "transit")
	viper.SetDefault("KMS_KV_MOUNT", "secret")
	viper.SetDefault("KMS_TIMEOUT_SECS", 10)
}

package kms

import "github.com/spf13/viper"

const (
	defaultKMSEthereumMount                   = "ethereum"
	defaultKMSPQCMount                        = "pqc"
	defaultKMSTransitMount                    = "transit"
	defaultKMSKVMount                         = "secret"
	defaultKMSKeyStoreMount                   = "key-store"
	defaultKMSKeyStoreWrapTTLSecs             = 60
	defaultKMSKeyStoreMaxWrapTTLSecs          = 300
	defaultKMSKeyStoreCedarDefaultOwnerPolicy = true
	defaultKMSTimeoutSecs                     = 10
)

type kmsConfig struct {
	OpenBaoProxyURL                 string
	EthereumMount                   string
	PQCMount                        string
	TransitMount                    string
	KVMount                         string
	KeyStoreMount                   string
	KeyStoreWrapTTLSecs             int
	KeyStoreMaxWrapTTLSecs          int
	KeyStoreCedarPolicyPath         string
	KeyStoreCedarDefaultOwnerPolicy bool
	TimeoutSecs                     int
}

func readFromEnv() *kmsConfig {
	setDefaults()

	return &kmsConfig{
		OpenBaoProxyURL:                 viper.GetString("KMS_OPENBAO_PROXY_URL"),
		EthereumMount:                   viper.GetString("KMS_ETHEREUM_MOUNT"),
		PQCMount:                        viper.GetString("KMS_PQC_MOUNT"),
		TransitMount:                    viper.GetString("KMS_TRANSIT_MOUNT"),
		KVMount:                         viper.GetString("KMS_KV_MOUNT"),
		KeyStoreMount:                   viper.GetString("KMS_KEY_STORE_MOUNT"),
		KeyStoreWrapTTLSecs:             viper.GetInt("KMS_KEY_STORE_WRAP_TTL_SECS"),
		KeyStoreMaxWrapTTLSecs:          viper.GetInt("KMS_KEY_STORE_MAX_WRAP_TTL_SECS"),
		KeyStoreCedarPolicyPath:         viper.GetString("KMS_KEY_STORE_CEDAR_POLICY_PATH"),
		KeyStoreCedarDefaultOwnerPolicy: viper.GetBool("KMS_KEY_STORE_CEDAR_DEFAULT_OWNER_POLICY"),
		TimeoutSecs:                     viper.GetInt("KMS_TIMEOUT_SECS"),
	}
}

func setDefaults() {
	viper.SetDefault("KMS_ETHEREUM_MOUNT", defaultKMSEthereumMount)
	viper.SetDefault("KMS_PQC_MOUNT", defaultKMSPQCMount)
	viper.SetDefault("KMS_TRANSIT_MOUNT", defaultKMSTransitMount)
	viper.SetDefault("KMS_KV_MOUNT", defaultKMSKVMount)
	viper.SetDefault("KMS_KEY_STORE_MOUNT", defaultKMSKeyStoreMount)
	viper.SetDefault("KMS_KEY_STORE_WRAP_TTL_SECS", defaultKMSKeyStoreWrapTTLSecs)
	viper.SetDefault("KMS_KEY_STORE_MAX_WRAP_TTL_SECS", defaultKMSKeyStoreMaxWrapTTLSecs)
	viper.SetDefault("KMS_KEY_STORE_CEDAR_POLICY_PATH", "")
	viper.SetDefault("KMS_KEY_STORE_CEDAR_DEFAULT_OWNER_POLICY", defaultKMSKeyStoreCedarDefaultOwnerPolicy)
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
	if next.KeyStoreMount == "" {
		next.KeyStoreMount = defaultKMSKeyStoreMount
	}
	if next.KeyStoreWrapTTLSecs == 0 {
		next.KeyStoreWrapTTLSecs = defaultKMSKeyStoreWrapTTLSecs
	}
	if next.KeyStoreMaxWrapTTLSecs == 0 {
		next.KeyStoreMaxWrapTTLSecs = defaultKMSKeyStoreMaxWrapTTLSecs
	}
	if next.KeyStoreMaxWrapTTLSecs < next.KeyStoreWrapTTLSecs {
		next.KeyStoreMaxWrapTTLSecs = next.KeyStoreWrapTTLSecs
	}
	if next.TimeoutSecs == 0 {
		next.TimeoutSecs = defaultKMSTimeoutSecs
	}
	return &next
}

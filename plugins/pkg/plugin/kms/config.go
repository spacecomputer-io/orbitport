package kms

import (
	"fmt"

	"github.com/spf13/viper"
)

const (
	defaultKMSEthereumMount         = "ethereum"
	defaultKMSPQCMount              = "pqc"
	defaultKMSTransitMount          = "transit"
	defaultKMSKVMount               = "secret"
	defaultKMSKeyStoreMount         = "key-store"
	defaultKMSTimeoutSecs           = 10
	defaultKMSDeletionSweepInterval = "1h"
	defaultKMSListKeysLimit         = 100
	defaultKMSMaxListKeysLimit      = 1000
	defaultKMSDeletionWindowDays    = 30
)

type kmsConfig struct {
	OpenBaoProxyURL           string
	EthereumMount             string
	PQCMount                  string
	TransitMount              string
	KVMount                   string
	KeyStoreMount             string
	KeyStoreCedarPolicyPath   string
	TimeoutSecs               int
	DeletionSweepInterval     string
	ListKeysDefaultLimit      int
	ListKeysMaxLimit          int
	DefaultDeletionWindowDays int
}

func readFromEnv() *kmsConfig {
	setDefaults()

	return &kmsConfig{
		OpenBaoProxyURL:           viper.GetString("KMS_OPENBAO_PROXY_URL"),
		EthereumMount:             viper.GetString("KMS_ETHEREUM_MOUNT"),
		PQCMount:                  viper.GetString("KMS_PQC_MOUNT"),
		TransitMount:              viper.GetString("KMS_TRANSIT_MOUNT"),
		KVMount:                   viper.GetString("KMS_KV_MOUNT"),
		KeyStoreMount:             viper.GetString("KMS_KEY_STORE_MOUNT"),
		KeyStoreCedarPolicyPath:   viper.GetString("KMS_KEY_STORE_CEDAR_POLICY_PATH"),
		TimeoutSecs:               viper.GetInt("KMS_TIMEOUT_SECS"),
		DeletionSweepInterval:     viper.GetString("KMS_DELETION_SWEEP_INTERVAL"),
		ListKeysDefaultLimit:      viper.GetInt("KMS_LIST_KEYS_DEFAULT_LIMIT"),
		ListKeysMaxLimit:          viper.GetInt("KMS_LIST_KEYS_MAX_LIMIT"),
		DefaultDeletionWindowDays: viper.GetInt("KMS_DEFAULT_DELETION_WINDOW_DAYS"),
	}
}

func setDefaults() {
	viper.SetDefault("KMS_ETHEREUM_MOUNT", defaultKMSEthereumMount)
	viper.SetDefault("KMS_PQC_MOUNT", defaultKMSPQCMount)
	viper.SetDefault("KMS_TRANSIT_MOUNT", defaultKMSTransitMount)
	viper.SetDefault("KMS_KV_MOUNT", defaultKMSKVMount)
	viper.SetDefault("KMS_KEY_STORE_MOUNT", defaultKMSKeyStoreMount)
	viper.SetDefault("KMS_KEY_STORE_CEDAR_POLICY_PATH", "")
	viper.SetDefault("KMS_TIMEOUT_SECS", defaultKMSTimeoutSecs)
	viper.SetDefault("KMS_DELETION_SWEEP_INTERVAL", defaultKMSDeletionSweepInterval)
	viper.SetDefault("KMS_LIST_KEYS_DEFAULT_LIMIT", defaultKMSListKeysLimit)
	viper.SetDefault("KMS_LIST_KEYS_MAX_LIMIT", defaultKMSMaxListKeysLimit)
	viper.SetDefault("KMS_DEFAULT_DELETION_WINDOW_DAYS", defaultKMSDeletionWindowDays)
}

func withKMSConfigDefaults(cfg *kmsConfig) *kmsConfig {
	if cfg == nil {
		cfg = &kmsConfig{}
	}
	next := *cfg
	if next.ListKeysDefaultLimit == 0 {
		next.ListKeysDefaultLimit = defaultKMSListKeysLimit
	}
	if next.ListKeysMaxLimit == 0 {
		next.ListKeysMaxLimit = defaultKMSMaxListKeysLimit
	}
	if next.DefaultDeletionWindowDays == 0 {
		next.DefaultDeletionWindowDays = defaultKMSDeletionWindowDays
	}
	if next.DeletionSweepInterval == "" {
		next.DeletionSweepInterval = defaultKMSDeletionSweepInterval
	}
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
	if next.TimeoutSecs == 0 {
		next.TimeoutSecs = defaultKMSTimeoutSecs
	}
	return &next
}

func validateLifecycleConfig(cfg *kmsConfig) error {
	if cfg.ListKeysDefaultLimit < 1 || cfg.ListKeysDefaultLimit > maxSupportedListKeysLimit {
		return fmt.Errorf("KMS_LIST_KEYS_DEFAULT_LIMIT must be between 1 and %d", maxSupportedListKeysLimit)
	}
	if cfg.ListKeysMaxLimit < 1 || cfg.ListKeysMaxLimit > maxSupportedListKeysLimit {
		return fmt.Errorf("KMS_LIST_KEYS_MAX_LIMIT must be between 1 and %d", maxSupportedListKeysLimit)
	}
	if cfg.ListKeysDefaultLimit > cfg.ListKeysMaxLimit {
		return fmt.Errorf("KMS_LIST_KEYS_DEFAULT_LIMIT must not exceed KMS_LIST_KEYS_MAX_LIMIT")
	}
	if cfg.DefaultDeletionWindowDays < minDeletionWindowDays || cfg.DefaultDeletionWindowDays > maxDeletionWindowDays {
		return fmt.Errorf("KMS_DEFAULT_DELETION_WINDOW_DAYS must be between %d and %d", minDeletionWindowDays, maxDeletionWindowDays)
	}
	return nil
}

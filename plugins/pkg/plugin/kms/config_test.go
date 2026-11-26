package kms

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestLifecycleConfigDefaults(t *testing.T) {
	cfg := withKMSConfigDefaults(nil)
	require.Equal(t, 100, cfg.ListKeysDefaultLimit)
	require.Equal(t, 1000, cfg.ListKeysMaxLimit)
	require.Equal(t, 30, cfg.DefaultDeletionWindowDays)
	require.NoError(t, validateLifecycleConfig(cfg))

	custom := &kmsConfig{ListKeysDefaultLimit: 20, ListKeysMaxLimit: 50, DefaultDeletionWindowDays: 14}
	next := withKMSConfigDefaults(custom)
	require.Equal(t, 20, next.ListKeysDefaultLimit)
	require.Equal(t, 50, next.ListKeysMaxLimit)
	require.Equal(t, 14, next.DefaultDeletionWindowDays)
	require.Empty(t, custom.TransitMount)
	require.NotEmpty(t, next.TransitMount)
}

func TestLifecycleConfigValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cfg    kmsConfig
		errKey string
	}{
		{"minimums", kmsConfig{ListKeysDefaultLimit: 1, ListKeysMaxLimit: 1, DefaultDeletionWindowDays: 7}, ""},
		{"maximums", kmsConfig{ListKeysDefaultLimit: 1000, ListKeysMaxLimit: 1000, DefaultDeletionWindowDays: 30}, ""},
		{"negative default", kmsConfig{ListKeysDefaultLimit: -1}, "KMS_LIST_KEYS_DEFAULT_LIMIT"},
		{"default above API ceiling", kmsConfig{ListKeysDefaultLimit: 1001}, "KMS_LIST_KEYS_DEFAULT_LIMIT"},
		{"negative max", kmsConfig{ListKeysMaxLimit: -1}, "KMS_LIST_KEYS_MAX_LIMIT"},
		{"max above API ceiling", kmsConfig{ListKeysMaxLimit: 1001}, "KMS_LIST_KEYS_MAX_LIMIT"},
		{"default above max", kmsConfig{ListKeysDefaultLimit: 100, ListKeysMaxLimit: 50}, "must not exceed"},
		{"window too short", kmsConfig{DefaultDeletionWindowDays: 6}, "KMS_DEFAULT_DELETION_WINDOW_DAYS"},
		{"window too long", kmsConfig{DefaultDeletionWindowDays: 31}, "KMS_DEFAULT_DELETION_WINDOW_DAYS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := newPluginWithConfig(&tc.cfg, nil)
			if tc.errKey == "" {
				require.NoError(t, err)
				t.Cleanup(p.Close)
			} else {
				require.ErrorContains(t, err, tc.errKey)
			}
		})
	}
}

func lifecycleConfigEnv(t *testing.T) {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.SetEnvPrefix("ORBITPORT")
	viper.AutomaticEnv()
	t.Setenv("ORBITPORT_KMS_OPENBAO_PROXY_URL", "http://127.0.0.1:8200")
	t.Setenv("ORBITPORT_KMS_KEY_STORE_CEDAR_POLICY_PATH", "")
	t.Setenv("ORBITPORT_KMS_DELETION_SWEEP_INTERVAL", "0")
	// Empty environment values exercise Viper's defaults, independent of the host.
	t.Setenv("ORBITPORT_KMS_LIST_KEYS_DEFAULT_LIMIT", "")
	t.Setenv("ORBITPORT_KMS_LIST_KEYS_MAX_LIMIT", "")
	t.Setenv("ORBITPORT_KMS_DEFAULT_DELETION_WINDOW_DAYS", "")
}

func TestLifecycleConfigFromEnvironment(t *testing.T) {
	lifecycleConfigEnv(t)
	p, err := NewPlugin()
	require.NoError(t, err)
	t.Cleanup(p.Close)
	require.Equal(t, uint32(100), p.listKeysDefaultLimit)
	require.Equal(t, uint32(1000), p.listKeysMaxLimit)
	require.Equal(t, uint32(30), p.defaultDeletionWindowDays)

	t.Setenv("ORBITPORT_KMS_LIST_KEYS_DEFAULT_LIMIT", "20")
	t.Setenv("ORBITPORT_KMS_LIST_KEYS_MAX_LIMIT", "50")
	t.Setenv("ORBITPORT_KMS_DEFAULT_DELETION_WINDOW_DAYS", "14")
	p, err = NewPlugin()
	require.NoError(t, err)
	t.Cleanup(p.Close)
	require.Equal(t, uint32(20), p.listKeysDefaultLimit)
	require.Equal(t, uint32(50), p.listKeysMaxLimit)
	require.Equal(t, uint32(14), p.defaultDeletionWindowDays)
}

func TestLifecycleConfigRejectsInvalidEnvironment(t *testing.T) {
	for _, key := range []string{
		"ORBITPORT_KMS_LIST_KEYS_DEFAULT_LIMIT",
		"ORBITPORT_KMS_LIST_KEYS_MAX_LIMIT",
		"ORBITPORT_KMS_DEFAULT_DELETION_WINDOW_DAYS",
	} {
		for _, value := range []string{"0", "-1", "not-a-number", "4294967296"} {
			t.Run(key+"/"+value, func(t *testing.T) {
				lifecycleConfigEnv(t)
				t.Setenv(key, value)
				p, err := NewPlugin()
				require.ErrorContains(t, err, key[len("ORBITPORT_"):])
				require.Nil(t, p)
			})
		}
	}
}

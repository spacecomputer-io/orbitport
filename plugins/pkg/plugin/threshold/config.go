package threshold

import "github.com/spf13/viper"

type thresholdConfig struct {
	TimeoutSecs        int
	SessionSecret      string
	RetryAttempts      int
	RetryBackoffMillis int
}

func readFromEnv() *thresholdConfig {
	setDefaults()

	return &thresholdConfig{
		TimeoutSecs:        viper.GetInt("THRESHOLD_TIMEOUT_SECS"),
		SessionSecret:      viper.GetString("THRESHOLD_SESSION_SECRET"),
		RetryAttempts:      viper.GetInt("THRESHOLD_RETRY_ATTEMPTS"),
		RetryBackoffMillis: viper.GetInt("THRESHOLD_RETRY_BACKOFF_MILLIS"),
	}
}

func setDefaults() {
	viper.SetDefault("THRESHOLD_TIMEOUT_SECS", 30)
	viper.SetDefault("THRESHOLD_RETRY_ATTEMPTS", 3)
	viper.SetDefault("THRESHOLD_RETRY_BACKOFF_MILLIS", 100)
}

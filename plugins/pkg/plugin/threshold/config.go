package threshold

import "github.com/spf13/viper"

type thresholdConfig struct {
	TimeoutSecs int
}

func readFromEnv() *thresholdConfig {
	setDefaults()

	return &thresholdConfig{
		TimeoutSecs: viper.GetInt("THRESHOLD_TIMEOUT_SECS"),
	}
}

func setDefaults() {
	viper.SetDefault("THRESHOLD_TIMEOUT_SECS", 30)
}

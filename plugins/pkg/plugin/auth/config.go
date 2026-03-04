package auth

import (
	"github.com/spf13/viper"
)

// authConfig is the configuration for the Auth0 plugin.
type authConfig struct {
	// Auth0Domain is the domain of the Auth0 instance.
	Auth0Domain string
	// Auth0Audience is the audience of the Auth0 instance.
	Auth0Audience string
	DisableAuth   bool
}

func readFromEnv() *authConfig {
	setDefaults()

	return &authConfig{
		Auth0Domain:   viper.GetString("AUTH0_DOMAIN"),
		Auth0Audience: viper.GetString("AUTH0_AUDIENCE"),
		DisableAuth:   viper.GetBool("DEV_DISABLE_AUTH"),
	}
}

func setDefaults() {
	viper.SetDefault("AUTH0_DOMAIN", "")
	viper.SetDefault("AUTH0_AUDIENCE", "")
	viper.SetDefault("DEV_DISABLE_AUTH", false) // defaults to secure
}

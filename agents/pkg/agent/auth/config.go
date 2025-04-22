package auth

import (
	"github.com/spf13/viper"
)

// authConfig is the configuration for the Auth0 agent.
type authConfig struct {
	// Auth0Domain is the domain of the Auth0 instance.
	Auth0Domain string
	// Auth0Audience is the audience of the Auth0 instance.
	Auth0Audience string
}

func readFromEnv() *authConfig {
	setDefaults()

	return &authConfig{
		Auth0Domain:   viper.GetString("AUTH0_DOMAIN"),
		Auth0Audience: viper.GetString("AUTH0_AUDIENCE"),
	}
}

func setDefaults() {
	viper.SetDefault("AUTH0_DOMAIN", "")
	viper.SetDefault("AUTH0_AUDIENCE", "")
}

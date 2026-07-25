package main

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

/// The Mocker is a CLI to start mocked services for the plugins.

type mockerConfig struct {
	// Service is the name of the service to mock.
	// Possible values: "crypto2_api" (default), "crypto2_auth".
	// Legacy aliases "aptosorbital_api" and "aptosorbital_auth" also work.
	Service string
	// The port to listen on. (default 8000)
	Port uint16
	// The profile to use. (default "happy")
	// Possible values: "happy", "offline"
	Profile Profile
}

func readFromEnv() *mockerConfig {
	_ = godotenv.Load()
	viper.SetEnvPrefix("OPMOCK") // Will read env vars like ORBITPORT_VARNAME
	viper.AutomaticEnv()         // Read in environment variables that match

	setDefaults()

	return &mockerConfig{
		Service: viper.GetString("SERVICE"),
		Port:    viper.GetUint16("PORT"),
		Profile: stringToProfile(viper.GetString("PROFILE")),
	}
}

func setDefaults() {
	viper.SetDefault("SERVICE", "crypto2_api")
	viper.SetDefault("PORT", 8000)
	viper.SetDefault("PROFILE", string(PROFILE_HAPPY_PATH))
}

type HttpServer interface {
	ListenAndServe(addr string)
}

func main() {
	cfg := readFromEnv()
	switch cfg.Service {
	case "crypto2_api", "aptosorbital_api":
		server := NewMockCrypto2API(cfg.Profile)
		server.ListenAndServe(fmt.Sprintf(":%d", cfg.Port))
	case "crypto2_auth", "aptosorbital_auth":
		server := NewMockCrypto2Auth(cfg.Profile)
		server.ListenAndServe(fmt.Sprintf(":%d", cfg.Port))
	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown service: %s\n", cfg.Service)
		os.Exit(1)
	}
}

type Profile string

const (
	// HAPPY_PATH is the happy path profile.
	PROFILE_HAPPY_PATH Profile = "happy"
	// PROFILE_OFFLINE is the offline profile.
	PROFILE_OFFLINE Profile = "offline"
)

func stringToProfile(s string) Profile {
	switch s {
	case "happy", "load":
		return PROFILE_HAPPY_PATH
	case "offline":
		return PROFILE_OFFLINE
	default:
		return PROFILE_HAPPY_PATH
	}
}

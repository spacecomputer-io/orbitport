package main

import (
	"fmt"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

/// The Mocker is a CLI to start mocked services for the agents.

type mockerConfig struct {
	// Service is the name of the service to mock.
	// Possible values: "aptosorbital_api" (default), "aptosorbital_auth"
	Service string
	// The port to listen on. (default 8000)
	Port uint16
}

func readFromEnv() *mockerConfig {
	_ = godotenv.Load()
	viper.SetEnvPrefix("OPMOCK") // Will read env vars like ORBITPORT_VARNAME
	viper.AutomaticEnv()         // Read in environment variables that match

	setDefaults()

	return &mockerConfig{
		Service: viper.GetString("SERVICE"),
		Port:    viper.GetUint16("PORT"),
	}
}

func setDefaults() {
	viper.SetDefault("SERVICE", "aptosorbital_api")
	viper.SetDefault("PORT", 8000)
}

type HttpServer interface {
	ListenAndServe(addr string)
}

func main() {
	cfg := readFromEnv()
	switch cfg.Service {
	case "aptosorbital_api":
		server := NewMockAptosOrbitalAPI()
		server.ListenAndServe(fmt.Sprintf(":%d", cfg.Port))
	case "aptosorbital_auth":
		server := NewMockAptosOrbitalAuth()
		server.ListenAndServe(fmt.Sprintf(":%d", cfg.Port))
	default:
		panic("Unknown service: " + cfg.Service)
	}
}

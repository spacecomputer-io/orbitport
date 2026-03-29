package core

import (
	"os"

	"github.com/joho/godotenv"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	"github.com/spf13/viper"
)

// GrpcPluginConfig contains the configuration for a grpc plugin.
type GrpcPluginConfig struct {
	// Plugin is the name of the plugin.
	// Can be one of:
	// - "aptosorbital" (default)
	// - "auth"
	// - "authnoop" (development only)
	Plugin string
	// GrpcPort is the port the grpc server listens on.
	GrpcPort uint16
	// MetricsPort is the port the metrics server listens on.
	MetricsPort uint16
}

// ReadFromEnv reads the configuration from the environment.
func ReadFromEnv() *GrpcPluginConfig {
	// if we running with '-e <path>' flag, load the env file
	logger := utils.GetLogger("orbitport:plugin")
	envFiles := make([]string, 0)
	if len(os.Args) > 2 && os.Args[1] == "-e" {
		logger.Infof("Using env file %s\n", os.Args[2])
		envFiles = append(envFiles, os.Args[2])
	}
	if err := godotenv.Load(envFiles...); err != nil && len(envFiles) > 0 {
		logger.Warnf("Failed to load env file(s) %v: %v", envFiles, err)
	}
	viper.SetEnvPrefix("ORBITPORT") // Will read env vars like ORBITPORT_VARNAME
	viper.AutomaticEnv()            // Read in environment variables that match

	setDefaults()

	return &GrpcPluginConfig{
		Plugin:      viper.GetString("PLUGIN"),
		GrpcPort:    viper.GetUint16("GRPC_PORT"),
		MetricsPort: viper.GetUint16("METRICS_PORT"),
	}
}

func setDefaults() {
	viper.SetDefault("PLUGIN", "aptosorbital")
	viper.SetDefault("GRPC_PORT", 50001)
	viper.SetDefault("METRICS_PORT", 9000)
}

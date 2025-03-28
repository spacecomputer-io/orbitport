package core

import (
	"os"

	"github.com/joho/godotenv"
	"github.com/spacecoinxyz/orbitport/agents/pkg/utils"
	"github.com/spf13/viper"
)

// GrpcAgentConfig contains the configuration for a grpc agent.
type GrpcAgentConfig struct {
	// Agent is the name of the agent.
	// Can be one of:
	// - "aptosorbital" (default)
	// - "auth"
	Agent string
	// GrpcPort is the port the grpc server listens on.
	GrpcPort uint16
	// MetricsPort is the port the metrics server listens on.
	MetricsPort uint16
}

// ReadFromEnv reads the configuration from the environment.
func ReadFromEnv() *GrpcAgentConfig {
	// if we running with '-e <path>' flag, load the env file
	envFiles := make([]string, 0)
	if len(os.Args) > 2 && os.Args[1] == "-e" {
		logger := utils.GetLogger("orbitport:agent")
		logger.Infof("Using env file %s\n", os.Args[2])
		envFiles = append(envFiles, os.Args[2])
	}
	_ = godotenv.Load(envFiles...)
	viper.SetEnvPrefix("ORBITPORT") // Will read env vars like ORBITPORT_VARNAME
	viper.AutomaticEnv()            // Read in environment variables that match

	setDefaults()

	return &GrpcAgentConfig{
		Agent:       viper.GetString("AGENT"),
		GrpcPort:    viper.GetUint16("GRPC_PORT"),
		MetricsPort: viper.GetUint16("METRICS_PORT"),
	}
}

func setDefaults() {
	viper.SetDefault("AGENT", "aptosorbital")
	viper.SetDefault("GRPC_PORT", 50001)
	viper.SetDefault("METRICS_PORT", 9000)
}

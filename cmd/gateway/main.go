package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
	gateway_api "github.com/spacecoinxyz/orbitport/internal/api"
	"github.com/spacecoinxyz/orbitport/internal/config"
	"github.com/spacecoinxyz/orbitport/internal/monitoring"
	"github.com/spacecoinxyz/orbitport/internal/randomness"
	"github.com/spacecoinxyz/orbitport/internal/utils"
)

func main() {
	logger := utils.GetLogger("orbitport")

	cfg := config.ReadFromEnv()
	logger.Debug("Configuration loaded")
	if err := startGateway(*cfg); err != nil {
		logger.Panic(err)
	}
}

// startGateway starts the gateway service.
func startGateway(cfg config.Config) error {
	gatewayHealthStatus.Set(healthStatusStarting)
	defer gatewayHealthStatus.Set(healthStatusDown)

	logger := utils.GetLogger("orbitport")

	go func(port uint16) {
		logger.Infof("Starting metrics server on port %d", port)
		_ = monitoring.StartServer(port)
	}(cfg.MetricsPort)

	// initialize services
	randService, err := randomness.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize randomness service: %w", err)
	}
	logger.Debug("Randomness service initialized")

	gin.SetMode(gin.ReleaseMode)
	r, err := gateway_api.NewRouter(cfg, gateway_api.Services{
		Randomness: randService,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize HTTP router: %w", err)
	}
	logger.Infof("HTTP router is ready, starting server on port %d", cfg.Port)
	gatewayHealthStatus.Set(healthStatusReady)
	if err := r.Run(fmt.Sprintf(":%d", cfg.Port)); err != nil {
		return fmt.Errorf("failed to run HTTP server: %w", err)
	}
	return nil
}

package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/spacecoinxyz/orbitport/internal/config"
	"github.com/spacecoinxyz/orbitport/internal/monitoring"
	"github.com/spacecoinxyz/orbitport/internal/randomness"
	randomness_common "github.com/spacecoinxyz/orbitport/internal/randomness/common"
	"github.com/spacecoinxyz/orbitport/internal/randomness/providers/aptosorbital"
	"github.com/spacecoinxyz/orbitport/internal/utils"
)

func main() {
	logger := utils.GetLogger("orbitport")

	if err := startGateway(logger); err != nil {
		logger.Panic(err)
	}
}

func startGateway(logger *utils.Logger) error {
	gatewayHealthStatus.Set(healthStatusStarting)
	defer gatewayHealthStatus.Set(healthStatusDown)

	cfg := config.ReadFromEnv()
	logger.Debug("Configuration loaded")
	go func(port uint16) {
		logger.Infof("Starting metrics server on port %d", port)
		_ = monitoring.StartServer(port)
	}(cfg.MetricsPort)

	randService, err := initRandomnessService(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize randomness service: %w", err)
	}
	logger.Debug("Randomness service initialized")
	r := initRouter(randService)
	logger.Infof("HTTP router is ready, starting server on port %d", cfg.Port)
	gatewayHealthStatus.Set(healthStatusReady)
	if err := r.Run(fmt.Sprintf(":%d", cfg.Port)); err != nil {
		return fmt.Errorf("failed to run HTTP server: %w", err)
	}
	return nil
}

func initRouter(randService randomness_common.Service) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	// TODO: enable to configure trusted proxies
	_ = r.SetTrustedProxies(nil)

	pingLogger := utils.GetLogger("orbitport:ping:api")

	r.GET("/ping", func(c *gin.Context) {
		pingLogger.Debug("Received ping request")
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})

	randLogger := utils.GetLogger("orbitport:randomness:api")

	r.GET("/v1/rand_seed", func(c *gin.Context) {
		randLogger.Debug("Received request for random seed")

		timer := prometheus.NewTimer(randRequestDuration)
		defer timer.ObserveDuration()

		randRequestTotal.WithLabelValues("recieved").Inc()

		seed, err := randService.GetRandomSeed()
		if err != nil {
			randLogger.Errorf("Failed to get random seed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{})
			randRequestTotal.WithLabelValues("failed").Inc()
			return
		}
		randLogger.Debug("Random seed retrieved")
		randRequestTotal.WithLabelValues("ok").Inc()
		c.JSON(http.StatusOK, gin.H{
			"seed": seed,
		})
	})

	return r
}

func initRandomnessService(cfg *config.Config) (randomness_common.Service, error) {
	aptosClient, err := aptosorbital.NewClient(
		aptosorbital.WithApiURL(cfg.AptosOrbitalApiUrl),
		aptosorbital.WithAuthURL(cfg.AptosOrbitalAuthUrl),
		aptosorbital.WithClientID(cfg.AptosOrbitalClientId),
		aptosorbital.WithClientSecret(cfg.AptosOrbitalClientSecret),
		aptosorbital.WithRateLimit(float64(cfg.AptosOrbitalRateLimit), 1),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Aptos Orbital client: %w", err)
	}

	return randomness.NewService(aptosClient), nil
}

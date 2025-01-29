package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/spacecoinxyz/stargate/internal/config"
	"github.com/spacecoinxyz/stargate/internal/randomness"
	randomness_common "github.com/spacecoinxyz/stargate/internal/randomness/common"
	"github.com/spacecoinxyz/stargate/internal/randomness/providers/aptosorbital"
	"github.com/spacecoinxyz/stargate/internal/utils"
)

func main() {
	logger := utils.GetLogger("stargate")
	cfg := config.ReadFromEnv()
	logger.Debug("Configuration loaded")
	randService, err := initRandomnessService(cfg)
	if err != nil {
		logger.Panic(err)
	}
	logger.Debug("Randomness service initialized")
	r := initRouter(randService)
	logger.Infof("HTTP router is ready, starting server on port %d", cfg.Port)
	if err := r.Run(fmt.Sprintf(":%d", cfg.Port)); err != nil {
		panic(err)
	}
}

func initRouter(randService randomness_common.Service) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	// TODO: enable to configure trusted proxies
	_ = r.SetTrustedProxies(nil)

	pingLogger := utils.GetLogger("stargate:ping:api")

	r.GET("/ping", func(c *gin.Context) {
		pingLogger.Debug("Received ping request")
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})

	randLogger := utils.GetLogger("stargate:randomness:api")

	r.GET("/v1/rand_seed", func(c *gin.Context) {
		randLogger.Debug("Received request for random seed")
		seed, err := randService.GetRandomSeed()
		if err != nil {
			randLogger.Errorf("Failed to get random seed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{})
			return
		}
		randLogger.Debug("Random seed retrieved")
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

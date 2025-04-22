package gateway_api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spacecomputerio/orbitport/internal/api/auth"
	"github.com/spacecomputerio/orbitport/internal/config"
	randomness_common "github.com/spacecomputerio/orbitport/internal/randomness/common"
	"github.com/spacecomputerio/orbitport/internal/utils"
)

type Services struct {
	Randomness randomness_common.Service
}

func NewRouter(cfg config.Config, services Services) (*gin.Engine, error) {
	r := gin.Default()

	trustedProxies := cfg.Proxies
	if len(trustedProxies) == 0 {
		trustedProxies = nil
	}
	if err := r.SetTrustedProxies(trustedProxies); err != nil {
		return nil, fmt.Errorf("failed to set trusted proxies: %w", err)
	}

	r.GET("/ping", pingRoute())

	authLogger := utils.GetLogger("orbitport:auth")
	// add Auth0 middleware if Auth0 domain is set, otherwise skip authentication
	if len(cfg.Auth0Domain) > 0 {
		authHandler, err := auth.Auth0Middleware(cfg.Auth0Domain, cfg.Auth0Audience)
		if err != nil {
			return nil, fmt.Errorf("failed to set up Auth0 middleware: %w", err)
		}
		r.Use(authHandler)
		authLogger.Info("Auth0 middleware is set, authentication is ON")
	} else if len(cfg.StaticAuthToken) > 0 {
		r.Use(auth.StaticTokenMiddleware(cfg.StaticAuthToken))
		authLogger.Warn("Static token auth middleware set, authentication is ON")
	} else {
		authLogger.Warn("Auth0 domain is not set, authentication is OFF")
	}

	randService := services.Randomness
	if randService == nil {
		return nil, fmt.Errorf("randomness service is required")
	}
	r.GET("/v1/rand_seed", randRoute(randService))
	// temp support for /api prefixed routes
	r.GET("/api/v1/rand_seed", randRoute(randService))

	return r, nil
}

func pingRoute() gin.HandlerFunc {
	pingRouteLogger := utils.GetLogger("orbitport:ping:api")

	return func(c *gin.Context) {
		pingRouteLogger.Debug("Received ping request")
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	}
}

func randRoute(randService randomness_common.Service) gin.HandlerFunc {
	randRouteLogger := utils.GetLogger("orbitport:randomness:api")

	return func(c *gin.Context) {
		randRouteLogger.Debug("Received request for random seed")

		timer := prometheus.NewTimer(RandRequestDuration)
		defer timer.ObserveDuration()

		RandRequestTotal.WithLabelValues("recieved").Inc()

		srcs := c.QueryArray("src")

		seed, err := randService.GetRandomSeed(c.Request.Context(), randomness_common.RandSourceFromStrings(srcs)...)
		if err != nil {
			randRouteLogger.Errorf("Failed to get random seed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{})
			RandRequestTotal.WithLabelValues("failed").Inc()
			return
		}
		randRouteLogger.Debug("Random seed retrieved")
		RandRequestTotal.WithLabelValues("ok").Inc()

		c.JSON(http.StatusOK, seed)
	}
}

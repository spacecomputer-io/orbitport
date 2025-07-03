package main

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/spacecomputerio/orbitport/plugins/pkg/core"
	"github.com/spacecomputerio/orbitport/plugins/pkg/core/health"
	"github.com/spacecomputerio/orbitport/plugins/pkg/plugin/aptosorbital"
	"github.com/spacecomputerio/orbitport/plugins/pkg/plugin/auth"
	"github.com/spacecomputerio/orbitport/plugins/pkg/plugin/beacon"
	"github.com/spacecomputerio/orbitport/plugins/pkg/plugin/ipfs"
	"github.com/spacecomputerio/orbitport/plugins/pkg/utils"
	"github.com/spacecomputerio/orbitport/plugins/proto"
)

func main() {
	utils.GetLogger("orbitport:plugin").Info("Initializing")

	cfg := core.ReadFromEnv()

	logger := utils.GetLogger(fmt.Sprintf("orbitport:plugin:%s", cfg.Plugin))

	grpcServer := grpc.NewServer()

	logger.Infof("Starting plugin %s", cfg.Plugin)

	switch cfg.Plugin {
	case "aptosorbital":
		plugin, err := aptosorbital.NewPlugin()
		if err != nil {
			panic(err)
		}
		proto.RegisterRandomnessPluginServer(grpcServer, plugin)
		logger.Info("Aptos Orbital plugin ready")
	case "auth":
		plugin, err := auth.NewPlugin()
		if err != nil {
			panic(err)
		}
		proto.RegisterAuthPluginServer(grpcServer, plugin)
		logger.Info("Auth plugin ready")
	case "ipfs":
		plugin, err := ipfs.NewPlugin()
		if err != nil {
			panic(err)
		}
		proto.RegisterIpfsPluginServer(grpcServer, plugin)
		logger.Info("IPFS plugin ready")
	case "beacon":
		beaconpn, err := beacon.NewPlugin()
		if err != nil {
			panic("beacon.newPlugin panic")
		}

		logger.Info("Beacon plugin ready")

		err = beaconpn.Start(context.Background())
		if err != nil {
			logger.Errorf("error starting beacon plugin: %v", err)
		}
		defer func() {
			err := beaconpn.Close()
			if err != nil {
				logger.Errorf("error closing beacon plugin: %v", err)
			}
		}()

	default:
		panic("unknown plugin")
	}

	healthCheck := func(_ context.Context) (health.HealthState, error) {
		return health.HealthStateHealthy, nil
	}
	healthServer := health.NewHealthServer(healthCheck)
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)

	go func() {
		logger.Infof("Starting metrics server on port %d", cfg.MetricsPort)
		err := core.ListenMetrics(cfg.MetricsPort)
		if err != nil {
			logger.Errorf("failed to start metrics server: %v", err)
		}
	}()

	logger.Infof("Starting gRPC server on port %d", cfg.GrpcPort)

	err := core.ListenGrpc(grpcServer, cfg.GrpcPort)
	if err != nil {
		panic(err)
	}
}

package main

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/spacecomputerio/orbitport/agents/pkg/agent/aptosorbital"
	"github.com/spacecomputerio/orbitport/agents/pkg/agent/auth"
	"github.com/spacecomputerio/orbitport/agents/pkg/agent/ipfs"
	"github.com/spacecomputerio/orbitport/agents/pkg/core"
	"github.com/spacecomputerio/orbitport/agents/pkg/core/health"
	"github.com/spacecomputerio/orbitport/agents/pkg/utils"
	"github.com/spacecomputerio/orbitport/agents/proto"
)

func main() {
	utils.GetLogger("orbitport:agent").Info("Initializing")

	cfg := core.ReadFromEnv()

	logger := utils.GetLogger(fmt.Sprintf("orbitport:agent:%s", cfg.Agent))

	grpcServer := grpc.NewServer()

	logger.Infof("Starting agent %s", cfg.Agent)

	switch cfg.Agent {
	case "aptosorbital":
		agent, err := aptosorbital.NewAgent()
		if err != nil {
			panic(err)
		}
		proto.RegisterRandomnessAgentServer(grpcServer, agent)
		logger.Info("Aptos Orbital agent ready")
	case "auth":
		agent, err := auth.NewAgent()
		if err != nil {
			panic(err)
		}
		proto.RegisterAuthAgentServer(grpcServer, agent)
		logger.Info("Auth agent ready")
	case "ipfs":
		agent, err := ipfs.NewAgent()
		if err != nil {
			panic(err)
		}
		proto.RegisterIpfsAgentServer(grpcServer, agent)
		logger.Info("IPFS agent ready")
	default:
		panic("unknown agent")
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

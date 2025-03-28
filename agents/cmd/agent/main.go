package main

import (
	"fmt"

	"github.com/spacecoinxyz/orbitport/agents/pkg/agent/aptosorbital"
	"github.com/spacecoinxyz/orbitport/agents/pkg/agent/auth"
	"github.com/spacecoinxyz/orbitport/agents/pkg/core"
	"github.com/spacecoinxyz/orbitport/agents/pkg/utils"
	"github.com/spacecoinxyz/orbitport/agents/proto"
	"google.golang.org/grpc"
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
	default:
		panic("unknown agent")
	}

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

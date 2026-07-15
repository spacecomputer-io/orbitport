package masterseed

import (
	"fmt"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func getAptosPluginClient(cfg masterSeedConfig) (*grpc.ClientConn, proto.RandomnessPluginClient, error) {
	conn, err := grpc.NewClient(
		cfg.AptosPlugin,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to Aptos plugin: %w", err)
	}

	client := proto.NewRandomnessPluginClient(conn)
	return conn, client, nil
}

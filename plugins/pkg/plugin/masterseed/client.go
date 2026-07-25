package masterseed

import (
	"fmt"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func getCrypto2PluginClient(cfg masterSeedConfig) (*grpc.ClientConn, proto.RandomnessPluginClient, error) {
	conn, err := grpc.NewClient(
		cfg.Crypto2Plugin,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to crypto2 plugin: %w", err)
	}

	client := proto.NewRandomnessPluginClient(conn)
	return conn, client, nil
}
